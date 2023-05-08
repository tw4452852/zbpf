const std = @import("std");
const print = std.debug.print;
pub const libbpf = @cImport({
    @cInclude("stdio.h");
    @cInclude("btf.h");
});

fn btf_dump_printf(ctx: ?*anyopaque, fmt: [*c]const u8, args: [*c]libbpf.struct___va_list_tag) callconv(.C) void {
    const fd = @ptrToInt(ctx);
    _ = libbpf.vdprintf(@intCast(c_int, fd), fmt, args);
}

pub fn main() !void {
    const btf = libbpf.btf__load_vmlinux_btf();
    if (btf == null) {
        print("failed to get BTF: {}\n", .{std.os.errno(-1)});
        return error.PARSE;
    }

    const d = libbpf.btf_dump__new(btf, btf_dump_printf, @intToPtr(?*anyopaque, @intCast(usize, std.io.getStdOut().handle)), null);
    if (d == null) {
        print("failed to create btf dumper: {}\n", .{std.os.errno(-1)});
        return error.DUMP;
    }
    defer libbpf.btf_dump__free(d);

    const n = libbpf.btf__type_cnt(btf);
    for (0..n) |i| {
        const err = libbpf.btf_dump__dump_type(d, @intCast(c_uint, i));
        if (err != 0) {
            print("failed to dump {}th btf type: {}\n", .{ i, std.os.errno(-1) });
            return error.DUMP;
        }
    }
}
