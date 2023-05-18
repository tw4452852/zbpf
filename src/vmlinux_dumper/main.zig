const std = @import("std");
const print = std.debug.print;
pub const libbpf = @cImport({
    @cInclude("stdio.h");
    @cInclude("btf.h");
});

fn btf_dump_printf(ctx: ?*anyopaque, fmt: [*c]const u8, args: @typeInfo(@typeInfo(@typeInfo(libbpf.btf_dump_printf_fn_t).Optional.child).Pointer.child).Fn.params[2].type.?) callconv(.C) void {
    const fd = @ptrToInt(ctx);
    _ = libbpf.vdprintf(@intCast(c_int, fd), fmt, args);
}

pub fn main() !void {
    const btf = libbpf.btf__load_vmlinux_btf();
    if (btf == null) {
        print("failed to get BTF: {}\n", .{std.os.errno(-1)});
        return error.PARSE;
    }

    const stdout = std.io.getStdOut();

    const d = libbpf.btf_dump__new(btf, btf_dump_printf, @intToPtr(?*anyopaque, @intCast(usize, stdout.handle)), null);
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

    for (0..n) |i| {
        const t = libbpf.btf__type_by_id(btf, @intCast(c_uint, i));
        if (libbpf.btf_kind(t) == libbpf.BTF_KIND_FUNC) {
            var buf: [256]u8 = undefined;
            const func_name = try std.fmt.bufPrintZ(&buf, "_zig_{s}", .{libbpf.btf__name_by_offset(btf, t[0].name_off)});
            const OPT = extern struct {
                sz: usize,
                field_name: [*c]const u8,
                indent_level: c_int = 0,
                strip_mods: bool = false,
            };
            var opt: OPT = .{
                .sz = @sizeOf(OPT),
                .field_name = func_name,
            };
            const err = libbpf.btf_dump__emit_type_decl(d, t[0].unnamed_0.type, @ptrCast(*libbpf.btf_dump_emit_type_decl_opts, &opt));
            if (err != 0) {
                print("failed to dump {}th btf type: {}\n", .{ i, std.os.errno(-1) });
                return error.DUMP;
            }
            try std.fmt.format(stdout, ";\n", .{});
        }
    }
}
