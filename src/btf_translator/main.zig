const std = @import("std");
const c = @cImport({
    @cInclude("btf.h");
    @cInclude("bpf.h");
});
const print = std.debug.print;
const assert = std.debug.assert;

var debug = false;

fn dprint(comptime fmt: []const u8, args: anytype) void {
    if (debug) {
        print(fmt, args);
    }
}

// btf_translator [-vmlinux/path/to/vmlinux] [-o/path/to/output_file] [-debug] [-syscalls]
pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();

    const gpa = arena.allocator();

    var it = std.process.args();
    _ = it.skip(); // skip process name
    var output: std.fs.File = std.io.getStdOut();
    var vmlinux_arg: ?[:0]const u8 = null;
    var include_syscalls = false;
    while (it.next()) |arg| {
        if (std.mem.startsWith(u8, arg, "-o")) {
            output = try std.fs.createFileAbsolute(arg["-o".len..], .{ .truncate = true });
        } else if (std.mem.startsWith(u8, arg, "-vmlinux")) {
            vmlinux_arg = vmlinux_arg orelse arg["-vmlinux".len..];
        } else if (std.mem.startsWith(u8, arg, "-debug")) {
            debug = true;
        } else if (std.mem.startsWith(u8, arg, "-syscalls")) {
            include_syscalls = true;
        } else {
            print("unknown argument: {s}\n", .{arg});
            std.process.exit(1);
        }
    }

    const btf = if (vmlinux_arg) |vmlinux| c.btf__parse(vmlinux, null) else c.btf__load_vmlinux_btf();
    if (btf == null) {
        print("failed to get BTF: {}\n", .{std.posix.errno(-1)});
        return error.PARSE;
    }

    defer output.close();
    const result = try translate(gpa, btf);
    const w = output.writer();
    try w.writeAll("pub const Kernel = @This();\n");
    try w.writeAll("pub const @\"void\" = anyopaque;\n");
    try w.writeAll(result);
    if (include_syscalls) {
        const syscalls = @embedFile("syscalls.zig");
        try w.writeAll("pub const kernel_syscalls = struct {\n");
        try w.writeAll(syscalls);
        try w.writeAll("};\n");
    }
}

const Allocator = std.mem.Allocator;
const NodeIndex = std.zig.Ast.Node.Index;
const NodeSubRange = std.zig.Ast.Node.SubRange;
const TokenIndex = std.zig.Ast.TokenIndex;
const TokenTag = std.zig.Token.Tag;

const Context = struct {
    gpa: Allocator,
    buf: std.ArrayList(u8),
    nodes: std.zig.Ast.NodeList = .{},
    extra_data: std.ArrayListUnmanaged(std.zig.Ast.Node.Index) = .empty,
    tokens: std.zig.Ast.TokenList = .{},

    fn addTokenFmt(ctx: *Context, tag: TokenTag, comptime format: []const u8, args: anytype) Allocator.Error!TokenIndex {
        const start_index = ctx.buf.items.len;
        try ctx.buf.writer().print(format ++ " ", args);

        try ctx.tokens.append(ctx.gpa, .{
            .tag = tag,
            .start = @as(u32, @intCast(start_index)),
        });

        return @as(u32, @intCast(ctx.tokens.len - 1));
    }

    fn addToken(ctx: *Context, tag: TokenTag, bytes: []const u8) Allocator.Error!TokenIndex {
        return ctx.addTokenFmt(tag, "{s}", .{bytes});
    }

    fn addIdentifier(ctx: *Context, bytes: []const u8) Allocator.Error!TokenIndex {
        if (std.zig.primitives.isPrimitive(bytes))
            return ctx.addTokenFmt(.identifier, "@\"{s}\"", .{bytes});
        return ctx.addTokenFmt(.identifier, "{p}", .{std.zig.fmtId(bytes)});
    }

    fn listToSpan(ctx: *Context, list: []const NodeIndex) Allocator.Error!NodeSubRange {
        try ctx.extra_data.appendSlice(ctx.gpa, list);
        return NodeSubRange{
            .start = @as(NodeIndex, @intCast(ctx.extra_data.items.len - list.len)),
            .end = @as(NodeIndex, @intCast(ctx.extra_data.items.len)),
        };
    }

    fn addNode(ctx: *Context, elem: std.zig.Ast.Node) Allocator.Error!NodeIndex {
        const result = @as(NodeIndex, @intCast(ctx.nodes.len));
        try ctx.nodes.append(ctx.gpa, elem);
        return result;
    }

    fn addExtra(ctx: *Context, extra: anytype) Allocator.Error!NodeIndex {
        const fields = std.meta.fields(@TypeOf(extra));
        try ctx.extra_data.ensureUnusedCapacity(ctx.gpa, fields.len);
        const result = @as(u32, @intCast(ctx.extra_data.items.len));
        inline for (fields) |field| {
            comptime std.debug.assert(field.type == NodeIndex);
            ctx.extra_data.appendAssumeCapacity(@field(extra, field.name));
        }
        return result;
    }
};

const BTFIndex = usize;
const Map = std.AutoHashMap(BTFIndex, []const u8);
const BTFKind = enum {
    unknown,
    int,
    ptr,
    array,
    @"struct",
    @"union",
    @"enum",
    fwd,
    typedef,
    @"volatile",
    @"const",
    restrict,
    func,
    func_proto,
    @"var",
    datasec,
    float,
    decl_tag,
    type_tag,
    enum64,
};
const Chain = std.ArrayList(BTFIndex);
const funcs_field_name = "kernel_funcs";

fn found_loop(chain: *const Chain, i: BTFIndex) bool {
    for (chain.items) |item| {
        if (item == i) return true;
    }
    return false;
}

fn get_kind(btf: ?*c.btf, i: BTFIndex) BTFKind {
    const t: *const c.btf_type = c.btf__type_by_id(btf, @intCast(i));
    return @enumFromInt(c.btf_kind(t));
}

fn add_child_node(btf: ?*c.btf, i: BTFIndex, names: *const Map, ctx: *Context, chain: *Chain) !NodeIndex {
    if (chain.items.len != 0) {
        if (names.get(i)) |name| {
            dprint(" {}({s})", .{ i, name });

            const t: *const c.btf_type = c.btf__type_by_id(btf, @intCast(i));
            const kind: BTFKind = @enumFromInt(c.btf_kind(t));

            return if (kind == .func) blk: {
                const funcs_field = try ctx.addNode(.{
                    .tag = .identifier,
                    .main_token = try ctx.addIdentifier(funcs_field_name),
                    .data = undefined,
                });
                break :blk try ctx.addNode(.{
                    .tag = .field_access,
                    .main_token = try ctx.addToken(.period, "."),
                    .data = .{
                        .lhs = funcs_field,
                        .rhs = try ctx.addIdentifier(name),
                    },
                });
            } else try ctx.addNode(.{
                .tag = .identifier,
                .main_token = try ctx.addIdentifier(name),
                .data = undefined,
            });
        }
    }
    const t: *const c.btf_type = c.btf__type_by_id(btf, @intCast(i));
    const kind: BTFKind = @enumFromInt(c.btf_kind(t));

    dprint(" {}({s} new)", .{ i, @tagName(kind) });

    return switch (kind) {
        .unknown => blk: {
            if (chain.getLastOrNull()) |parent| {
                const pt: *const c.btf_type = c.btf__type_by_id(btf, @intCast(parent));
                if (c.btf_kind(pt) == c.BTF_KIND_PTR) break :blk try ctx.addNode(.{
                    .tag = .identifier,
                    .main_token = try ctx.addToken(.identifier, "anyopaque"),
                    .data = undefined,
                });
            }
            break :blk try ctx.addNode(.{
                .tag = .identifier,
                .main_token = try ctx.addToken(.identifier, "void"),
                .data = undefined,
            });
        },
        .int => blk: {
            const signed = (c.btf_int_encoding(t) & c.BTF_INT_SIGNED == 1);
            break :blk try ctx.addNode(.{
                .tag = .identifier,
                .main_token = try ctx.addTokenFmt(.identifier, "{s}{d}", .{ if (signed) "i" else "u", t.unnamed_0.size * 8 }),
                .data = undefined,
            });
        },
        .float => try ctx.addNode(.{
            .tag = .identifier,
            .main_token = try ctx.addTokenFmt(.identifier, "f{d}", .{t.unnamed_0.size * 8}),
            .data = undefined,
        }),
        .ptr => blk: {
            var pointee = t.unnamed_0.type;
            var pkind = get_kind(btf, pointee);
            while (pkind == .typedef or pkind == .@"const" or pkind == .@"volatile" or pkind == .restrict) {
                const pt: *const c.btf_type = c.btf__type_by_id(btf, pointee);
                pointee = pt.unnamed_0.type;
                pkind = get_kind(btf, pointee);
            }
            // https://github.com/ziglang/zig/issues/12325
            if (pkind == .func_proto or pkind == .func) {
                pointee = 0;
            }

            try chain.append(i);
            defer _ = chain.pop();
            break :blk try ctx.addNode(.{
                .tag = .optional_type,
                .main_token = try ctx.addToken(.question_mark, "?"),
                .data = .{
                    .lhs = try ctx.addNode(.{
                        .tag = .ptr_type_aligned,
                        .main_token = if (pointee == 0 or pkind == .fwd)
                            try ctx.addToken(.asterisk, "*")
                        else mt: {
                            const res = try ctx.addToken(.l_bracket, "[");
                            _ = try ctx.addToken(.asterisk, "*");
                            _ = try ctx.addToken(.r_bracket, "]");
                            break :mt res;
                        },
                        .data = .{
                            .lhs = 0,
                            .rhs = try add_child_node(btf, pointee, names, ctx, chain),
                        },
                    }),
                    .rhs = undefined,
                },
            });
        },
        .fwd => blk: {
            const opaque_tok = try ctx.addToken(.keyword_opaque, "opaque");
            _ = try ctx.addToken(.l_brace, "{");
            _ = try ctx.addToken(.r_brace, "}");

            break :blk try ctx.addNode(.{
                .tag = .container_decl_two,
                .main_token = opaque_tok,
                .data = .{
                    .lhs = 0,
                    .rhs = 0,
                },
            });
        },
        .typedef, .@"volatile", .@"const", .restrict => blk: {
            try chain.append(i);
            defer _ = chain.pop();
            break :blk try add_child_node(btf, t.unnamed_0.type, names, ctx, chain);
        },
        .@"enum", .enum64 => blk: {
            const vlen: u16 = c.btf_vlen(t);
            const signed: bool = c.btf_kflag(t);
            const vals = c.btf_enum(t);
            const val64s = c.btf_enum64(t);
            var members = std.ArrayList(NodeIndex).init(ctx.gpa);
            try members.ensureUnusedCapacity(vlen);
            defer members.deinit();

            const enum_tok = try ctx.addToken(.keyword_enum, "enum");
            const arg_node = arg: {
                _ = try ctx.addToken(.l_paren, "(");
                const arg = try ctx.addNode(.{
                    .tag = .identifier,
                    .main_token = try ctx.addTokenFmt(.identifier, "{s}{d}", .{
                        if (signed) "i" else "u",
                        if (t.unnamed_0.size != 0) t.unnamed_0.size * 8 else if (kind == .enum64) @as(usize, 64) else 32,
                    }),
                    .data = undefined,
                });
                _ = try ctx.addToken(.r_paren, ")");
                break :arg arg;
            };
            _ = try ctx.addToken(.l_brace, "{");
            var seen = std.AutoHashMap(u64, void).init(ctx.gpa);
            defer seen.deinit();
            for (0..vlen) |vi| {
                const key: u64 = if (kind == .enum64) c.btf_enum64_value(&val64s[vi]) else @intCast(@as(u32, @bitCast(vals[vi].val)));
                if (seen.contains(key)) continue;
                try seen.putNoClobber(key, {});

                const name_tok = try ctx.addIdentifier(std.mem.sliceTo(c.btf__name_by_offset(btf, if (kind == .enum64) val64s[vi].name_off else vals[vi].name_off), 0));
                _ = try ctx.addToken(.equal, "=");
                const is_neg = signed and if (kind == .enum64) @clz(c.btf_enum64_value(&val64s[vi])) == 0 else @clz(vals[vi].val) == 0;
                const abs_val: u64 =
                    if (kind == .enum64 and is_neg) @abs(@as(i64, @bitCast(c.btf_enum64_value(&val64s[vi])))) else if (kind == .@"enum" and is_neg) @abs(vals[vi].val) else if (kind == .enum64) c.btf_enum64_value(&val64s[vi]) else @intCast(@as(u32, @bitCast(vals[vi].val)));
                const init_tok = if (is_neg) try ctx.addNode(.{
                    .tag = .negation,
                    .main_token = try ctx.addToken(.minus, "-"),
                    .data = .{
                        .lhs = try ctx.addNode(.{
                            .tag = .number_literal,
                            .main_token = try ctx.addTokenFmt(.number_literal, "{}", .{abs_val}),
                            .data = undefined,
                        }),
                        .rhs = undefined,
                    },
                }) else try ctx.addNode(.{
                    .tag = .number_literal,
                    .main_token = try ctx.addTokenFmt(.number_literal, "{}", .{abs_val}),
                    .data = undefined,
                });
                try members.append(try ctx.addNode(.{
                    .tag = .container_field_init,
                    .main_token = name_tok,
                    .data = .{
                        .lhs = 0,
                        .rhs = init_tok,
                    },
                }));
                _ = try ctx.addToken(.comma, ",");
            }
            _ = try ctx.addToken(.r_brace, "}");

            const span = try ctx.listToSpan(members.items);
            break :blk try ctx.addNode(.{
                .tag = if (members.items.len == 0) .container_decl_arg else .container_decl_arg_trailing,
                .main_token = enum_tok,
                .data = .{
                    .lhs = arg_node,
                    .rhs = try ctx.addExtra(span),
                },
            });
        },
        .array => blk: {
            const array: *const c.struct_btf_array = c.btf_array(t);
            const elem_type = array.type;
            const len = array.nelems;

            const l_bracket = try ctx.addToken(.l_bracket, "[");
            const len_expr = try ctx.addNode(.{
                .tag = .number_literal,
                .main_token = try ctx.addTokenFmt(.number_literal, "{d}", .{len}),
                .data = undefined,
            });
            _ = try ctx.addToken(.r_bracket, "]");

            if (found_loop(chain, i)) {
                @panic(try std.fmt.allocPrint(ctx.gpa, "{} array loop: {any}\n", .{ i, chain.items }));
            }
            try chain.append(i);
            defer _ = chain.pop();
            const elem_type_expr = try add_child_node(btf, elem_type, names, ctx, chain);

            break :blk try ctx.addNode(.{
                .tag = .array_type,
                .main_token = l_bracket,
                .data = .{
                    .lhs = len_expr,
                    .rhs = elem_type_expr,
                },
            });
        },
        .@"struct" => blk: {
            const vlen: u16 = c.btf_vlen(t);
            const sz = t.unnamed_0.size;
            const m: [*c]const c.struct_btf_member = c.btf_members(t);
            var members = std.ArrayList(NodeIndex).init(ctx.gpa);
            try members.ensureUnusedCapacity(vlen);
            defer members.deinit();

            if (found_loop(chain, i)) {
                @panic(try std.fmt.allocPrint(ctx.gpa, "{} struct loop: {any}\n", .{ i, chain.items }));
            }
            try chain.append(i);
            defer _ = chain.pop();

            _ = try ctx.addToken(.keyword_extern, "extern");
            const struct_tok = try ctx.addToken(.keyword_struct, "struct");

            _ = try ctx.addToken(.l_brace, "{");
            var bitfield_off_begin: ?usize = null;
            var cur_bitoff: usize = 0;

            const add_field = struct {
                fn f(_ctx: *Context, prefix: []const u8, begin: usize, _bits: usize) !NodeIndex {
                    const name_tok = try _ctx.addTokenFmt(.identifier, "{s}_offset_{d}_{d}", .{ prefix, begin, begin + _bits });
                    _ = try _ctx.addToken(.colon, ":");
                    const type_expr = try _ctx.addNode(.{
                        .tag = .identifier,
                        .main_token = try _ctx.addTokenFmt(.identifier, "u{d}", .{_bits}),
                        .data = undefined,
                    });
                    const ret = try _ctx.addNode(.{
                        .tag = .container_field_init,
                        .main_token = name_tok,
                        .data = .{
                            .lhs = type_expr,
                            .rhs = 0,
                        },
                    });
                    _ = try _ctx.addToken(.comma, ",");
                    return ret;
                }
            }.f;

            for (0..vlen) |vi| {
                const m_sz = c.btf_member_bitfield_size(t, @intCast(vi));
                const m_off = c.btf_member_bit_offset(t, @intCast(vi));

                // Record the first bitfield position
                if (m_sz > 0 and bitfield_off_begin == null) {
                    bitfield_off_begin = m_off;
                }

                // Merge all accumulated bitfields
                if (bitfield_off_begin != null and m_sz == 0) {
                    const bits = m_off - bitfield_off_begin.?;
                    cur_bitoff = m_off;
                    bitfield_off_begin = null;

                    // TODO: packed struct
                    // The reason for divCeil is that some unused fields may be missing in btf, e.g. struct ioam6_trace_hdr.
                    const bytes = try std.math.divCeil(usize, bits, 8);
                    for (0..bytes) |n| {
                        try members.append(try add_field(ctx, "_zig_merged_bitfieds", m_off - bits + (n * 8), 8));
                    }
                }

                // Only handle non-bitfield here, bitfield will be accumulated to be merged later
                if (m_sz == 0) {
                    // Add padding when necessary
                    if (cur_bitoff < m_off) {
                        const bytes = try std.math.divExact(usize, m_off - cur_bitoff, 8);
                        for (0..bytes) |n| {
                            try members.append(try add_field(ctx, "_zig_padding", cur_bitoff + n * 8, 8));
                        }
                    }

                    const name_tok = if (m[vi].name_off != 0)
                        try ctx.addIdentifier(std.mem.sliceTo(c.btf__name_by_offset(btf, m[vi].name_off), 0))
                    else name: {
                        const name = try std.fmt.allocPrint(ctx.gpa, "field{}", .{vi});
                        defer ctx.gpa.free(name);
                        break :name try ctx.addIdentifier(name);
                    };
                    _ = try ctx.addToken(.colon, ":");

                    const type_expr = try add_child_node(btf, m[vi].type, names, ctx, chain);

                    try members.append(try ctx.addNode(.{
                        .tag = .container_field_init,
                        .main_token = name_tok,
                        .data = .{
                            .lhs = type_expr,
                            .rhs = 0,
                        },
                    }));
                    _ = try ctx.addToken(.comma, ",");
                }

                cur_bitoff = m_off + if (m_sz > 0) m_sz else sz: {
                    const byte_sz = c.btf__resolve_size(btf, m[vi].type);
                    break :sz if (byte_sz < 0) 0 else @as(usize, @intCast(byte_sz * 8));
                };
            }
            // Trailing bits
            if (bitfield_off_begin) |begin| {
                const bytes = try std.math.divExact(usize, sz * 8 - begin, 8);
                for (0..bytes) |n| {
                    try members.append(try add_field(ctx, "_zig_merged_bitfieds", cur_bitoff + n * 8, 8));
                }
            } else if (cur_bitoff < sz * 8) {
                const bytes = try std.math.divExact(usize, sz * 8 - cur_bitoff, 8);
                for (0..bytes) |n| {
                    try members.append(try add_field(ctx, "_zig_padding", cur_bitoff + n * 8, 8));
                }
            }
            _ = try ctx.addToken(.r_brace, "}");

            const span = try ctx.listToSpan(members.items);
            break :blk if (members.items.len == 0)
                try ctx.addNode(.{
                    .tag = .container_decl_two,
                    .main_token = struct_tok,
                    .data = .{
                        .lhs = 0,
                        .rhs = 0,
                    },
                })
            else
                try ctx.addNode(.{
                    .tag = .container_decl_trailing,
                    .main_token = struct_tok,
                    .data = .{
                        .lhs = span.start,
                        .rhs = span.end,
                    },
                });
        },
        .@"union" => blk: {
            const vlen: u16 = c.btf_vlen(t);
            const m: [*c]const c.struct_btf_member = c.btf_members(t);
            const members = try ctx.gpa.alloc(NodeIndex, vlen);
            defer ctx.gpa.free(members);

            if (found_loop(chain, i)) {
                @panic(try std.fmt.allocPrint(ctx.gpa, "{} union loop: {any}\n", .{ i, chain.items }));
            }
            try chain.append(i);
            defer _ = chain.pop();

            _ = try ctx.addToken(.keyword_extern, "extern");
            const union_tok = try ctx.addToken(.keyword_union, "union");

            _ = try ctx.addToken(.l_brace, "{");
            for (0..vlen) |vi| {
                const name_tok = if (m[vi].name_off != 0)
                    try ctx.addIdentifier(std.mem.sliceTo(c.btf__name_by_offset(btf, m[vi].name_off), 0))
                else name: {
                    const name = try std.fmt.allocPrint(ctx.gpa, "field{}", .{vi});
                    defer ctx.gpa.free(name);
                    break :name try ctx.addIdentifier(name);
                };
                _ = try ctx.addToken(.colon, ":");

                const type_expr = try add_child_node(btf, m[vi].type, names, ctx, chain);

                members[vi] = try ctx.addNode(.{
                    .tag = .container_field_init,
                    .main_token = name_tok,
                    .data = .{
                        .lhs = type_expr,
                        .rhs = 0,
                    },
                });
                _ = try ctx.addToken(.comma, ",");
            }
            _ = try ctx.addToken(.r_brace, "}");

            const span = try ctx.listToSpan(members);
            break :blk if (members.len == 0)
                try ctx.addNode(.{
                    .tag = .container_decl_two,
                    .main_token = union_tok,
                    .data = .{
                        .lhs = 0,
                        .rhs = 0,
                    },
                })
            else
                try ctx.addNode(.{
                    .tag = .container_decl_trailing,
                    .main_token = union_tok,
                    .data = .{
                        .lhs = span.start,
                        .rhs = span.end,
                    },
                });
        },
        .func_proto => blk: {
            const ret_type = t.unnamed_0.type;
            const m: [*c]const c.btf_param = c.btf_params(t);
            const vlen: u16 = c.btf_vlen(t);
            const params = try ctx.gpa.alloc(NodeIndex, vlen);
            defer ctx.gpa.free(params);

            if (found_loop(chain, i)) {
                @panic(try std.fmt.allocPrint(ctx.gpa, "{} func_proto loop: {any}\n", .{ i, chain.items }));
            }
            try chain.append(i);
            defer _ = chain.pop();

            const fn_token = try ctx.addToken(.keyword_fn, "fn");
            _ = try ctx.addToken(.l_paren, "(");
            for (0..vlen) |vi| {
                if (vi != 0) _ = try ctx.addToken(.comma, ",");
                if (vi == vlen - 1 and m[vi].type == 0) {
                    //_ = try ctx.addToken(.ellipsis3, "..."); TODO
                    break;
                }
                if (m[vi].name_off != 0) {
                    _ = try ctx.addIdentifier(std.mem.sliceTo(c.btf__name_by_offset(btf, m[vi].name_off), 0));
                } else {
                    const name = try std.fmt.allocPrint(ctx.gpa, "arg{}", .{vi});
                    defer ctx.gpa.free(name);
                    _ = try ctx.addIdentifier(name);
                }

                _ = try ctx.addToken(.colon, ":");

                params[vi] = try add_child_node(btf, m[vi].type, names, ctx, chain);
            }
            _ = try ctx.addToken(.r_paren, ")");
            const span = try ctx.listToSpan(params);

            const return_type_expr = try add_child_node(btf, ret_type, names, ctx, chain);

            break :blk if (vlen == 0)
                try ctx.addNode(.{
                    .tag = .fn_proto_simple,
                    .main_token = fn_token,
                    .data = .{
                        .lhs = 0,
                        .rhs = return_type_expr,
                    },
                })
            else
                try ctx.addNode(.{
                    .tag = .fn_proto_multi,
                    .main_token = fn_token,
                    .data = .{
                        .lhs = try ctx.addExtra(NodeSubRange{
                            .start = span.start,
                            .end = span.end,
                        }),
                        .rhs = return_type_expr,
                    },
                });
        },
        .func => blk: {
            const main_token = try ctx.addToken(.asterisk, "*");
            _ = try ctx.addToken(.keyword_const, "const");

            if (found_loop(chain, i)) {
                @panic(try std.fmt.allocPrint(ctx.gpa, "{} func loop: {any}\n", .{ i, chain.items }));
            }
            try chain.append(i);
            defer _ = chain.pop();
            break :blk try ctx.addNode(.{
                .tag = .ptr_type_aligned,
                .main_token = main_token,
                .data = .{
                    .lhs = 0,
                    .rhs = try add_child_node(btf, t.unnamed_0.type, names, ctx, chain),
                },
            });
        },
        .@"var", .datasec, .decl_tag, .type_tag => {
            var buf: [32]u8 = undefined;
            @panic(try std.fmt.bufPrint(&buf, "unsupported kind: {s}", .{@tagName(kind)}));
        },
    };
}

pub fn translate(gpa: Allocator, btf: ?*c.struct_btf) ![:0]const u8 {
    var ctx = Context{
        .gpa = gpa,
        .buf = std.ArrayList(u8).init(gpa),
    };
    defer ctx.buf.deinit();
    defer ctx.nodes.deinit(gpa);
    defer ctx.extra_data.deinit(gpa);
    defer ctx.tokens.deinit(gpa);

    try ctx.nodes.append(gpa, .{
        .tag = .root,
        .main_token = 0,
        .data = .{
            .lhs = undefined,
            .rhs = undefined,
        },
    });

    const root_members = blk: {
        var result = std.ArrayList(NodeIndex).init(gpa);
        defer result.deinit();
        var names = Map.init(gpa);
        defer {
            var it = names.valueIterator();
            while (it.next()) |name| gpa.free(name.*);
            names.deinit();
        }
        var chain = Chain.init(gpa);
        defer chain.deinit();
        var seen = std.StringHashMap(void).init(gpa);
        defer seen.deinit();

        for (1..c.btf__type_cnt(btf)) |i| {
            const t: *const c.btf_type = c.btf__type_by_id(btf, @intCast(i));
            const kind: BTFKind = @enumFromInt(c.btf_kind(t));

            const name = name: switch (kind) {
                .int, .float, .fwd, .typedef, .func => {
                    const name = try gpa.dupe(u8, std.mem.sliceTo(c.btf__name_by_offset(btf, t.name_off), 0));
                    std.mem.replaceScalar(u8, name, ' ', '_');
                    break :name name;
                },
                .ptr => {
                    const pointee = t.unnamed_0.type;
                    const pointee_t: *const c.btf_type = c.btf__type_by_id(btf, @intCast(pointee));
                    const pointee_name: [:0]const u8 = std.mem.sliceTo(c.btf__name_by_offset(btf, pointee_t.name_off), 0);
                    break :name if (pointee_name.len != 0)
                        try std.fmt.allocPrint(gpa, "ptr_to_{s}", .{pointee_name})
                    else
                        try std.fmt.allocPrint(gpa, "ptr_{d}", .{i});
                },
                .@"enum", .enum64, .@"struct", .@"union" => {
                    const name: [:0]const u8 = std.mem.sliceTo(c.btf__name_by_offset(btf, t.name_off), 0);
                    break :name if (name.len != 0)
                        try std.fmt.allocPrint(gpa, "{s}", .{name})
                    else
                        try std.fmt.allocPrint(gpa, "{s}_{d}", .{ @tagName(kind), i });
                },

                .func_proto,
                .array,
                .@"volatile",
                .@"const",
                .restrict,
                .@"var",
                .datasec,
                .decl_tag,
                .type_tag,
                => try std.fmt.allocPrint(gpa, "{s}_{d}", .{ @tagName(kind), i }),
                .unknown => unreachable,
            };

            const gop = try seen.getOrPut(name);
            const uniq_name = if (gop.found_existing and kind != .func) name: {
                const new_name = try std.fmt.allocPrint(gpa, "{s}__{d}", .{ name, i });
                gpa.free(name);
                break :name new_name;
            } else name;

            try names.putNoClobber(i, uniq_name);
        }

        var funcs_num: usize = 0;
        for (1..c.btf__type_cnt(btf)) |i| {
            const t: *const c.btf_type = c.btf__type_by_id(btf, @intCast(i));
            const kind: BTFKind = @enumFromInt(c.btf_kind(t));

            switch (kind) {
                .@"var", .datasec, .decl_tag, .type_tag => {
                    dprint("skip {s} {s}\n", .{ @tagName(kind), std.mem.sliceTo(c.btf__name_by_offset(btf, t.name_off), 0) });
                    continue;
                },
                .func => {
                    funcs_num += 1;
                    continue;
                },
                else => {},
            }

            dprint("{} {s}:", .{ i, @tagName(kind) });
            defer dprint("\n", .{});
            _ = try ctx.addToken(.keyword_pub, "pub");
            const const_tok = try ctx.addToken(.keyword_const, "const");
            _ = try ctx.addIdentifier(names.get(i).?);
            _ = try ctx.addToken(.equal, "=");
            chain.clearRetainingCapacity();
            const child = try add_child_node(btf, i, &names, &ctx, &chain);
            _ = try ctx.addToken(.semicolon, ";");

            const idx = try ctx.addNode(.{
                .tag = .simple_var_decl,
                .main_token = const_tok,
                .data = .{
                    .lhs = 0,
                    .rhs = child,
                },
            });
            try result.append(idx);
        }

        if (funcs_num > 0) {
            _ = try ctx.addToken(.keyword_pub, "pub");
            const func_const_tok = try ctx.addToken(.keyword_const, "const");
            _ = try ctx.addIdentifier(funcs_field_name);
            _ = try ctx.addToken(.equal, "=");

            const struct_tok = try ctx.addToken(.keyword_struct, "struct");
            _ = try ctx.addToken(.l_brace, "{");
            var members = std.ArrayList(NodeIndex).init(gpa);
            defer members.deinit();
            seen.clearRetainingCapacity();
            for (1..c.btf__type_cnt(btf)) |i| {
                const t: *const c.btf_type = c.btf__type_by_id(btf, @intCast(i));
                const kind: BTFKind = @enumFromInt(c.btf_kind(t));
                const name = std.mem.sliceTo(c.btf__name_by_offset(btf, t.name_off), 0);

                if (kind != .func or seen.contains(name)) continue;
                try seen.put(name, {});

                dprint("{} {s}:", .{ i, @tagName(kind) });
                defer dprint("\n", .{});
                _ = try ctx.addToken(.keyword_pub, "pub");
                const const_tok = try ctx.addToken(.keyword_const, "const");
                _ = try ctx.addIdentifier(names.get(i).?);
                _ = try ctx.addToken(.equal, "=");
                chain.clearRetainingCapacity();
                const child = try add_child_node(btf, i, &names, &ctx, &chain);
                _ = try ctx.addToken(.semicolon, ";");

                const idx = try ctx.addNode(.{
                    .tag = .simple_var_decl,
                    .main_token = const_tok,
                    .data = .{
                        .lhs = 0,
                        .rhs = child,
                    },
                });
                try members.append(idx);
            }
            _ = try ctx.addToken(.r_brace, "}");
            _ = try ctx.addToken(.semicolon, ";");
            const span = try ctx.listToSpan(members.items);
            const decl = try ctx.addNode(.{
                .tag = .container_decl_trailing,
                .main_token = struct_tok,
                .data = .{
                    .lhs = span.start,
                    .rhs = span.end,
                },
            });

            try result.append(try ctx.addNode(.{
                .tag = .simple_var_decl,
                .main_token = func_const_tok,
                .data = .{
                    .lhs = 0,
                    .rhs = decl,
                },
            }));
        }

        break :blk try ctx.listToSpan(result.items);
    };
    dprint("source: {s}\n", .{ctx.buf.items});

    ctx.nodes.items(.data)[0] = .{
        .lhs = root_members.start,
        .rhs = root_members.end,
    };

    try ctx.tokens.append(gpa, .{
        .tag = .eof,
        .start = @as(u32, @intCast(ctx.buf.items.len)),
    });

    const source_code = try ctx.buf.toOwnedSliceSentinel(0);
    var tree = std.zig.Ast{
        .source = source_code,
        .tokens = ctx.tokens.toOwnedSlice(),
        .nodes = ctx.nodes.toOwnedSlice(),
        .extra_data = try ctx.extra_data.toOwnedSlice(gpa),
        .errors = &.{},
        .mode = .zig,
    };

    defer tree.deinit(gpa);
    defer gpa.free(tree.source);

    var buffer = std.ArrayList(u8).init(gpa);
    defer buffer.deinit();
    try tree.renderToArrayList(&buffer, .{});

    return buffer.toOwnedSliceSentinel(0);
}

fn verify_generated(source_code: [:0]const u8, gpa: std.mem.Allocator) !void {
    var tree = try std.zig.Ast.parse(gpa, source_code, .zig);
    defer tree.deinit(gpa);
    var zir = try std.zig.AstGen.generate(gpa, tree);
    defer zir.deinit(gpa);
    if (zir.hasCompileErrors()) {
        var wip_errors: std.zig.ErrorBundle.Wip = undefined;
        try wip_errors.init(gpa);
        defer wip_errors.deinit();
        try wip_errors.addZirErrorMessages(zir, tree, source_code, "generated");
        var error_bundle = try wip_errors.toOwnedBundle("");
        defer error_bundle.deinit(gpa);
        error_bundle.renderToStdErr(std.zig.Color.renderOptions(.auto));
        print("generated:\n{s}\n", .{source_code});
        return error.FAILED;
    }
}

test "dup name" {
    const gpa = std.testing.allocator;
    const btf = c.btf__new_empty();
    assert(c.libbpf_get_error(btf) == 0);
    defer c.btf__free(btf);

    assert(c.btf__add_int(btf, "foo", 1, c.BTF_INT_CHAR) > 0);
    assert(c.btf__add_int(btf, "foo", 4, c.BTF_INT_SIGNED) > 0);

    const got = try translate(gpa, btf);
    defer gpa.free(got);
    const expect =
        \\pub const foo = u8;
        \\pub const foo__2 = i32;
        \\
    ;
    try std.testing.expectEqualStrings(expect, got);
    try verify_generated(got, gpa);
}

test "int" {
    const gpa = std.testing.allocator;
    const btf = c.btf__new_empty();
    assert(c.libbpf_get_error(btf) == 0);
    defer c.btf__free(btf);

    assert(c.btf__add_int(btf, "foo ", 1, c.BTF_INT_CHAR) > 0);
    assert(c.btf__add_int(btf, "bar", 4, c.BTF_INT_SIGNED) > 0);
    assert(c.btf__add_int(btf, "buz", 1, c.BTF_INT_BOOL) > 0);

    const got = try translate(gpa, btf);
    defer gpa.free(got);
    const expect =
        \\pub const foo_ = u8;
        \\pub const bar = i32;
        \\pub const buz = u8;
        \\
    ;
    try std.testing.expectEqualStrings(expect, got);
    try verify_generated(got, gpa);
}

test "ptr int" {
    const gpa = std.testing.allocator;
    const btf = c.btf__new_empty();
    assert(c.libbpf_get_error(btf) == 0);
    defer c.btf__free(btf);

    const t = c.btf__add_int(btf, "foo", 4, 0);
    assert(t > 0);
    assert(c.btf__add_ptr(btf, t) > 0);

    const got = try translate(gpa, btf);
    defer gpa.free(got);
    const expect =
        \\pub const foo = u32;
        \\pub const ptr_to_foo = ?[*]foo;
        \\
    ;
    try std.testing.expectEqualStrings(expect, got);
    try verify_generated(got, gpa);
}

test "nested ptr" {
    const gpa = std.testing.allocator;
    const btf = c.btf__new_empty();
    assert(c.libbpf_get_error(btf) == 0);
    defer c.btf__free(btf);

    const t = c.btf__add_int(btf, "foo", 4, 0);
    assert(t > 0);
    const p = c.btf__add_ptr(btf, t);
    assert(p > 0);
    assert(c.btf__add_ptr(btf, p) > 0);

    const got = try translate(gpa, btf);
    defer gpa.free(got);
    const expect =
        \\pub const foo = u32;
        \\pub const ptr_to_foo = ?[*]foo;
        \\pub const ptr_3 = ?[*]ptr_to_foo;
        \\
    ;
    try std.testing.expectEqualStrings(expect, got);
    try verify_generated(got, gpa);
}

test "void ptr" {
    const gpa = std.testing.allocator;
    const btf = c.btf__new_empty();
    assert(c.libbpf_get_error(btf) == 0);
    defer c.btf__free(btf);

    const p = c.btf__add_ptr(btf, 0);
    assert(p > 0);

    const got = try translate(gpa, btf);
    defer gpa.free(got);
    const expect =
        \\pub const ptr_1 = ?*anyopaque;
        \\
    ;
    try std.testing.expectEqualStrings(expect, got);
    try verify_generated(got, gpa);
}

test "function ptr" {
    const gpa = std.testing.allocator;
    const btf = c.btf__new_empty();
    assert(c.libbpf_get_error(btf) == 0);
    defer c.btf__free(btf);

    const proto = c.btf__add_func_proto(btf, 0);
    assert(proto > 0);
    const func = c.btf__add_func(btf, "bar", c.BTF_FUNC_GLOBAL, proto);
    assert(func > 0);
    const const_proto = c.btf__add_const(btf, proto);
    assert(const_proto > 0);
    const volatile_func = c.btf__add_volatile(btf, proto);
    assert(volatile_func > 0);
    assert(c.btf__add_ptr(btf, volatile_func) > 0);
    assert(c.btf__add_ptr(btf, const_proto) > 0);

    const got = try translate(gpa, btf);
    defer gpa.free(got);
    const expect =
        \\pub const func_proto_1 = fn () void;
        \\pub const const_3 = func_proto_1;
        \\pub const volatile_4 = func_proto_1;
        \\pub const ptr_5 = ?*anyopaque;
        \\pub const ptr_6 = ?*anyopaque;
        \\pub const kernel_funcs = struct {
        \\    pub const bar = *const func_proto_1;
        \\};
        \\
    ;
    try std.testing.expectEqualStrings(expect, got);
    try verify_generated(got, gpa);
}

test "float" {
    const gpa = std.testing.allocator;
    const btf = c.btf__new_empty();
    assert(c.libbpf_get_error(btf) == 0);
    defer c.btf__free(btf);

    assert(c.btf__add_float(btf, "foo", 2) > 0);

    const got = try translate(gpa, btf);
    defer gpa.free(got);
    const expect =
        \\pub const foo = f16;
        \\
    ;
    try std.testing.expectEqualStrings(expect, got);
    try verify_generated(got, gpa);
}

test "ptr fwd" {
    const gpa = std.testing.allocator;
    const btf = c.btf__new_empty();
    assert(c.libbpf_get_error(btf) == 0);
    defer c.btf__free(btf);

    const s = c.btf__add_fwd(btf, "foo_s", c.BTF_FWD_STRUCT);
    assert(s > 0);
    assert(c.btf__add_ptr(btf, s) > 0);
    const u = c.btf__add_fwd(btf, "foo_u", c.BTF_FWD_UNION);
    assert(u > 0);
    assert(c.btf__add_ptr(btf, u) > 0);

    const got = try translate(gpa, btf);
    defer gpa.free(got);
    const expect =
        \\pub const foo_s = opaque {};
        \\pub const ptr_to_foo_s = ?*foo_s;
        \\pub const foo_u = opaque {};
        \\pub const ptr_to_foo_u = ?*foo_u;
        \\
    ;
    try std.testing.expectEqualStrings(expect, got);
    try verify_generated(got, gpa);
}

test "typedef" {
    const gpa = std.testing.allocator;
    const btf = c.btf__new_empty();
    assert(c.libbpf_get_error(btf) == 0);
    defer c.btf__free(btf);

    const s = c.btf__add_fwd(btf, "foo_s", c.BTF_FWD_STRUCT);
    assert(s > 0);
    const p = c.btf__add_ptr(btf, s);
    assert(p > 0);
    assert(c.btf__add_typedef(btf, "bar", p) > 0);

    const got = try translate(gpa, btf);
    defer gpa.free(got);
    const expect =
        \\pub const foo_s = opaque {};
        \\pub const ptr_to_foo_s = ?*foo_s;
        \\pub const bar = ptr_to_foo_s;
        \\
    ;
    try std.testing.expectEqualStrings(expect, got);
    try verify_generated(got, gpa);
}

test "enum" {
    const gpa = std.testing.allocator;
    const btf = c.btf__new_empty();
    assert(c.libbpf_get_error(btf) == 0);
    defer c.btf__free(btf);

    assert(c.btf__add_enum(btf, "foo", 4) > 0);
    assert(c.btf__add_enum_value(btf, "foo_1", -1) == 0);
    assert(c.btf__add_enum_value(btf, "foo_2", 1) == 0);
    assert(c.btf__add_enum_value(btf, "foo_3", 0x80000000) == 0);
    assert(c.btf__add_enum_value(btf, "foo_4", 1) == 0);
    assert(c.btf__add_enum64(btf, "bar", 8, true) > 0);
    assert(c.btf__add_enum64_value(btf, "bar_1", 2) == 0);
    assert(c.btf__add_enum64_value(btf, "bar_2", 3) == 0);
    assert(c.btf__add_enum64_value(btf, "bar_3", 0xf0000000) == 0);
    assert(c.btf__add_enum64_value(btf, "bar_4", @bitCast(@as(i64, -128))) == 0);

    const got = try translate(gpa, btf);
    defer gpa.free(got);
    const expect =
        \\pub const foo = enum(i32) {
        \\    foo_1 = -1,
        \\    foo_2 = 1,
        \\    foo_3 = -2147483648,
        \\};
        \\pub const bar = enum(i64) {
        \\    bar_1 = 2,
        \\    bar_2 = 3,
        \\    bar_3 = 4026531840,
        \\    bar_4 = -128,
        \\};
        \\
    ;
    try std.testing.expectEqualStrings(expect, got);
    try verify_generated(got, gpa);
}

test "empty enum" {
    const gpa = std.testing.allocator;
    const btf = c.btf__new_empty();
    assert(c.libbpf_get_error(btf) == 0);
    defer c.btf__free(btf);

    assert(c.btf__add_enum(btf, "foo", 4) > 0);

    const got = try translate(gpa, btf);
    defer gpa.free(got);
    const expect =
        \\pub const foo = enum(u32) {};
        \\
    ;
    try std.testing.expectEqualStrings(expect, got);
    try verify_generated(got, gpa);
}

test "array" {
    const gpa = std.testing.allocator;
    const btf = c.btf__new_empty();
    assert(c.libbpf_get_error(btf) == 0);
    defer c.btf__free(btf);

    const t = c.btf__add_int(btf, "foo", 4, 0);
    assert(t > 0);
    const a = c.btf__add_array(btf, t, t, 3);
    assert(a > 0);
    assert(c.btf__add_array(btf, t, a, 3) > 0);

    const got = try translate(gpa, btf);
    defer gpa.free(got);
    const expect =
        \\pub const foo = u32;
        \\pub const array_2 = [3]foo;
        \\pub const array_3 = [3]array_2;
        \\
    ;
    try std.testing.expectEqualStrings(expect, got);
    try verify_generated(got, gpa);
}

test "struct" {
    const gpa = std.testing.allocator;
    const btf = c.btf__new_empty();
    assert(c.libbpf_get_error(btf) == 0);
    defer c.btf__free(btf);

    const t = c.btf__add_int(btf, "foo", 4, 0);
    assert(t > 0);
    const p = c.btf__add_ptr(btf, t);
    assert(p > 0);
    assert(c.btf__add_struct(btf, "bar", 8) > 0);
    assert(c.btf__add_field(btf, "f1", t, 0, 0) == 0);
    assert(c.btf__add_field(btf, null, p, 32, 0) == 0);

    const got = try translate(gpa, btf);
    defer gpa.free(got);
    const expect =
        \\pub const foo = u32;
        \\pub const ptr_to_foo = ?[*]foo;
        \\pub const bar = extern struct {
        \\    f1: foo,
        \\    field1: ptr_to_foo,
        \\};
        \\
    ;
    try std.testing.expectEqualStrings(expect, got);
    try verify_generated(got, gpa);
}

test "empty struct" {
    const gpa = std.testing.allocator;
    const btf = c.btf__new_empty();
    assert(c.libbpf_get_error(btf) == 0);
    defer c.btf__free(btf);

    assert(c.btf__add_struct(btf, "bar", 0) > 0);

    const got = try translate(gpa, btf);
    defer gpa.free(got);
    const expect =
        \\pub const bar = extern struct {};
        \\
    ;
    try std.testing.expectEqualStrings(expect, got);
    try verify_generated(got, gpa);
}

test "ptr loop" {
    const gpa = std.testing.allocator;
    const btf = c.btf__new_empty();
    assert(c.libbpf_get_error(btf) == 0);
    defer c.btf__free(btf);

    const t = c.btf__add_int(btf, "foo", 4, 0);
    assert(t > 0);
    const p = c.btf__add_ptr(btf, 0);
    assert(p > 0);
    const s = c.btf__add_struct(btf, "bar", 8);
    assert(s > 0);
    assert(c.btf__add_field(btf, "f1", t, 0, 0) == 0);
    assert(c.btf__add_field(btf, "f2", p, 32, 0) == 0);
    const pt: *c.btf_type = @constCast(c.btf__type_by_id(btf, @intCast(p)));
    pt.unnamed_0.type = @intCast(s);

    const got = try translate(gpa, btf);
    defer gpa.free(got);
    const expect =
        \\pub const foo = u32;
        \\pub const ptr_to_bar = ?[*]bar;
        \\pub const bar = extern struct {
        \\    f1: foo,
        \\    f2: ptr_to_bar,
        \\};
        \\
    ;
    try std.testing.expectEqualStrings(expect, got);
    try verify_generated(got, gpa);
}

test "union" {
    const gpa = std.testing.allocator;
    const btf = c.btf__new_empty();
    assert(c.libbpf_get_error(btf) == 0);
    defer c.btf__free(btf);

    const t = c.btf__add_int(btf, "foo", 4, 0);
    assert(t > 0);
    const p = c.btf__add_ptr(btf, t);
    assert(p > 0);
    assert(c.btf__add_union(btf, "bar", 4) > 0);
    assert(c.btf__add_field(btf, "f1", t, 0, 0) == 0);
    assert(c.btf__add_field(btf, null, p, 0, 0) == 0);

    const got = try translate(gpa, btf);
    defer gpa.free(got);
    const expect =
        \\pub const foo = u32;
        \\pub const ptr_to_foo = ?[*]foo;
        \\pub const bar = extern union {
        \\    f1: foo,
        \\    field1: ptr_to_foo,
        \\};
        \\
    ;
    try std.testing.expectEqualStrings(expect, got);
    try verify_generated(got, gpa);
}

test "empty union" {
    const gpa = std.testing.allocator;
    const btf = c.btf__new_empty();
    assert(c.libbpf_get_error(btf) == 0);
    defer c.btf__free(btf);

    assert(c.btf__add_union(btf, "bar", 0) > 0);

    const got = try translate(gpa, btf);
    defer gpa.free(got);
    const expect =
        \\pub const bar = extern union {};
        \\
    ;
    try std.testing.expectEqualStrings(expect, got);
    try verify_generated(got, gpa);
}

test "function" {
    const gpa = std.testing.allocator;
    const btf = c.btf__new_empty();
    assert(c.libbpf_get_error(btf) == 0);
    defer c.btf__free(btf);

    const t = c.btf__add_int(btf, "foo", 4, 0);
    assert(t > 0);
    const p = c.btf__add_ptr(btf, t);
    assert(p > 0);
    const proto = c.btf__add_func_proto(btf, 0);
    assert(proto > 0);
    assert(c.btf__add_func_param(btf, "a0", t) == 0);
    assert(c.btf__add_func_param(btf, null, p) == 0);
    assert(c.btf__add_func(btf, "foo", c.BTF_FUNC_GLOBAL, proto) > 0);
    const proto1 = c.btf__add_func_proto(btf, p);
    assert(proto1 > 0);
    assert(c.btf__add_func(btf, "buz", c.BTF_FUNC_GLOBAL, proto1) > 0);

    const got = try translate(gpa, btf);
    defer gpa.free(got);
    const expect =
        \\pub const foo = u32;
        \\pub const ptr_to_foo = ?[*]foo;
        \\pub const func_proto_3 = fn (a0: foo, arg1: ptr_to_foo) void;
        \\pub const func_proto_5 = fn () ptr_to_foo;
        \\pub const kernel_funcs = struct {
        \\    pub const foo = *const func_proto_3;
        \\    pub const buz = *const func_proto_5;
        \\};
        \\
    ;
    try std.testing.expectEqualStrings(expect, got);
    try verify_generated(got, gpa);
}

test "volatile" {
    const gpa = std.testing.allocator;
    const btf = c.btf__new_empty();
    assert(c.libbpf_get_error(btf) == 0);
    defer c.btf__free(btf);

    const t = c.btf__add_int(btf, "foo", 1, c.BTF_INT_CHAR);
    assert(t > 0);
    const v = c.btf__add_volatile(btf, t);
    assert(v > 0);
    assert(c.btf__add_ptr(btf, v) > 0);

    const got = try translate(gpa, btf);
    defer gpa.free(got);
    const expect =
        \\pub const foo = u8;
        \\pub const volatile_2 = foo;
        \\pub const ptr_3 = ?[*]foo;
        \\
    ;
    try std.testing.expectEqualStrings(expect, got);
    try verify_generated(got, gpa);
}

test "const" {
    const gpa = std.testing.allocator;
    const btf = c.btf__new_empty();
    assert(c.libbpf_get_error(btf) == 0);
    defer c.btf__free(btf);

    const t = c.btf__add_int(btf, "foo", 1, c.BTF_INT_CHAR);
    assert(t > 0);
    const v = c.btf__add_const(btf, t);
    assert(v > 0);
    assert(c.btf__add_ptr(btf, v) > 0);

    const got = try translate(gpa, btf);
    defer gpa.free(got);
    const expect =
        \\pub const foo = u8;
        \\pub const const_2 = foo;
        \\pub const ptr_3 = ?[*]foo;
        \\
    ;
    try std.testing.expectEqualStrings(expect, got);
    try verify_generated(got, gpa);
}

test "restrict" {
    const gpa = std.testing.allocator;
    const btf = c.btf__new_empty();
    assert(c.libbpf_get_error(btf) == 0);
    defer c.btf__free(btf);

    const t = c.btf__add_int(btf, "foo", 1, c.BTF_INT_CHAR);
    assert(t > 0);
    const v = c.btf__add_restrict(btf, t);
    assert(v > 0);
    assert(c.btf__add_ptr(btf, v) > 0);

    const got = try translate(gpa, btf);
    defer gpa.free(got);
    const expect =
        \\pub const foo = u8;
        \\pub const restrict_2 = foo;
        \\pub const ptr_3 = ?[*]foo;
        \\
    ;
    try std.testing.expectEqualStrings(expect, got);
    try verify_generated(got, gpa);
}

test "bitfields" {
    const gpa = std.testing.allocator;
    const btf = c.btf__new_empty();
    assert(c.libbpf_get_error(btf) == 0);
    defer c.btf__free(btf);

    const t = c.btf__add_int(btf, "foo", 4, 0);
    assert(t > 0);
    const p = c.btf__add_ptr(btf, t);
    assert(p > 0);
    assert(c.btf__add_struct(btf, "bar", 8) > 0);
    assert(c.btf__add_field(btf, "f1", t, 0, 1) == 0);
    assert(c.btf__add_field(btf, "f2", t, 3, 3) == 0);
    assert(c.btf__add_field(btf, "f3", p, 32, 0) == 0);

    const got = try translate(gpa, btf);
    defer gpa.free(got);
    const expect =
        \\pub const foo = u32;
        \\pub const ptr_to_foo = ?[*]foo;
        \\pub const bar = extern struct {
        \\    _zig_merged_bitfieds_offset_0_8: u8,
        \\    _zig_merged_bitfieds_offset_8_16: u8,
        \\    _zig_merged_bitfieds_offset_16_24: u8,
        \\    _zig_merged_bitfieds_offset_24_32: u8,
        \\    f3: ptr_to_foo,
        \\};
        \\
    ;
    try std.testing.expectEqualStrings(expect, got);
    try verify_generated(got, gpa);
}

test "volatile const void ptr" {
    const gpa = std.testing.allocator;
    const btf = c.btf__new_empty();
    assert(c.libbpf_get_error(btf) == 0);
    defer c.btf__free(btf);

    const t = c.btf__add_const(btf, 0);
    assert(t > 0);
    const v = c.btf__add_volatile(btf, t);
    assert(v > 0);
    assert(c.btf__add_ptr(btf, v) > 0);

    const got = try translate(gpa, btf);
    defer gpa.free(got);
    const expect =
        \\pub const const_1 = void;
        \\pub const volatile_2 = const_1;
        \\pub const ptr_3 = ?*anyopaque;
        \\
    ;
    try std.testing.expectEqualStrings(expect, got);
    try verify_generated(got, gpa);
}

test "dup function" {
    const gpa = std.testing.allocator;
    const btf = c.btf__new_empty();
    assert(c.libbpf_get_error(btf) == 0);
    defer c.btf__free(btf);

    const proto = c.btf__add_func_proto(btf, 0);
    assert(proto > 0);
    assert(c.btf__add_func(btf, "foo", c.BTF_FUNC_GLOBAL, proto) > 0);
    assert(c.btf__add_func(btf, "foo", c.BTF_FUNC_GLOBAL, proto) > 0);

    const got = try translate(gpa, btf);
    defer gpa.free(got);
    const expect =
        \\pub const func_proto_1 = fn () void;
        \\pub const kernel_funcs = struct {
        \\    pub const foo = *const func_proto_1;
        \\};
        \\
    ;
    try std.testing.expectEqualStrings(expect, got);
    try verify_generated(got, gpa);
}
