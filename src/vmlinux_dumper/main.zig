const std = @import("std");
const print = std.debug.print;
pub const libbpf = @cImport({
    @cInclude("stdio.h");
    @cInclude("btf.h");
});

fn btf_dump_printf(ctx: ?*anyopaque, fmt: [*c]const u8, args: @typeInfo(@typeInfo(@typeInfo(libbpf.btf_dump_printf_fn_t).Optional.child).Pointer.child).Fn.params[2].type.?) callconv(.C) void {
    const fd = @intFromPtr(ctx);
    _ = libbpf.vdprintf(@intCast(fd), fmt, args);
}

// vmlinux_dumper [path_to_vmlinux]
pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();

    const allocator = arena.allocator();

    var it = std.process.args();
    _ = it.skip(); // skip process name
    const btf = if (it.next()) |vmlinux| libbpf.btf__parse(vmlinux, null) else libbpf.btf__load_vmlinux_btf();
    if (btf == null) {
        print("failed to get BTF: {}\n", .{std.posix.errno(-1)});
        return error.PARSE;
    }

    const stdout = std.io.getStdOut();

    const d = libbpf.btf_dump__new(btf, btf_dump_printf, @ptrFromInt(@as(usize, @intCast(stdout.handle))), null);
    if (d == null) {
        print("failed to create btf dumper: {}\n", .{std.posix.errno(-1)});
        return error.DUMP;
    }
    defer libbpf.btf_dump__free(d);

    const n = libbpf.btf__type_cnt(btf);
    for (0..n) |i| {
        const err = libbpf.btf_dump__dump_type(d, @intCast(i));
        if (err != 0) {
            print("failed to dump {}th btf type: {}\n", .{ i, std.posix.errno(-1) });
            return error.DUMP;
        }
    }

    var funcs = std.StringHashMap(void).init(allocator);
    defer funcs.deinit();

    for (0..n) |i| {
        const t = libbpf.btf__type_by_id(btf, @intCast(i));
        if (libbpf.btf_kind(t) == libbpf.BTF_KIND_FUNC) {
            var buf: [256]u8 = undefined;
            const func_name = try std.fmt.bufPrintZ(&buf, "_zig_{s}", .{libbpf.btf__name_by_offset(btf, t[0].name_off)});
            if (funcs.get(func_name) != null) continue;

            // NOTE: redefine due to the original one has bitfields
            const OPT = extern struct {
                sz: usize,
                field_name: [*c]const u8,
                indent_level: c_int = 0,
                strip_mods: bool = false,
            };
            var opt = std.mem.zeroInit(OPT, .{
                .sz = @sizeOf(OPT),
                .field_name = func_name,
            });
            const err = libbpf.btf_dump__emit_type_decl(d, t[0].unnamed_0.type, @ptrCast(&opt));
            if (err != 0) {
                print("failed to dump {}th btf type: {} for function {s}\n", .{ i, std.posix.errno(-1), func_name });
                return error.DUMP;
            }
            try std.fmt.format(stdout, ";\n", .{});

            try funcs.put(try allocator.dupe(u8, func_name), {});
        }
    }

    try std.fmt.format(stdout, "#include <syscalls.h>\n", .{});
}
