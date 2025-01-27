const std = @import("std");
const c = @cImport({
    @cInclude("btf.h");
});
const print = std.debug.print;
const assert = std.debug.assert;

var debug = false;

fn dprint(comptime fmt: []const u8, args: anytype) void {
    if (debug) {
        print(fmt, args);
    }
}

// gen_vmlinux_offset_tests [-vmlinux/path/to/vmlinux] [-o/path/to/output_file] [-debug]
pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();

    const gpa = arena.allocator();

    var it = std.process.args();
    _ = it.skip(); // skip process name
    var output: std.fs.File = std.io.getStdOut();
    var vmlinux_arg: ?[:0]const u8 = null;
    while (it.next()) |arg| {
        if (std.mem.startsWith(u8, arg, "-o")) {
            output = try std.fs.createFileAbsolute(arg["-o".len..], .{ .truncate = true });
        } else if (std.mem.startsWith(u8, arg, "-vmlinux")) {
            vmlinux_arg = vmlinux_arg orelse arg["-vmlinux".len..];
        } else if (std.mem.startsWith(u8, arg, "-debug")) {
            debug = true;
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
    const w = output.writer();
    try w.writeAll("const vmlinux = @import(\"vmlinux\");\n");
    try w.writeAll("const std = @import(\"std\");\n");

    // Check structure size and non-bitfield offsets are consistent with btf
    for (1..c.btf__type_cnt(btf)) |i| {
        const t: *const c.btf_type = c.btf__type_by_id(btf, @intCast(i));
        if (c.btf_kind(t) == c.BTF_KIND_STRUCT) {
            const struct_sz = t.unnamed_0.size;
            const m: [*c]const c.struct_btf_member = c.btf_members(t);
            const vlen: u16 = c.btf_vlen(t);
            const btf_name: [:0]const u8 = std.mem.sliceTo(c.btf__name_by_offset(btf, t.name_off), 0);
            const struct_name = if (btf_name.len != 0)
                try gpa.dupe(u8, btf_name)
            else
                try std.fmt.allocPrint(gpa, "struct_{d}", .{i});

            const uniq_name = try std.fmt.allocPrint(gpa, "{s}__{d}", .{ struct_name, i });

            try w.print("test \"{s}\" {{\n", .{uniq_name});
            try w.print("const name = if (@hasDecl(vmlinux, \"{s}\")) \"{s}\" else \"{s}\";\n", .{ uniq_name, uniq_name, struct_name });
            defer w.writeAll("}\n") catch unreachable;

            try w.print("try std.testing.expectEqual({}, @sizeOf(@field(vmlinux, name)));\n", .{struct_sz});
            for (0..vlen) |vi| {
                const m_sz = c.btf_member_bitfield_size(t, @intCast(vi));
                const m_off = c.btf_member_bit_offset(t, @intCast(vi));

                // TODO: skip bitfield right now
                if (m_sz != 0) continue;

                const field_name = if (m[vi].name_off != 0)
                    try gpa.dupe(u8, std.mem.sliceTo(c.btf__name_by_offset(btf, m[vi].name_off), 0))
                else
                    try std.fmt.allocPrint(gpa, "field{}", .{vi});

                try w.print("try std.testing.expectEqual({}, @bitOffsetOf(@field(vmlinux, name), \"{s}\"));\n", .{ m_off, field_name });
            }
        }
    }
}
