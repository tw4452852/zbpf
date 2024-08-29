const std = @import("std");
const root = @import("root.zig");
const build_options = @import("@build_options");
const testing = std.testing;
const allocator = testing.allocator;
const print = std.debug.print;
pub const libbpf = @cImport({
    @cInclude("btf.h");
});

const structParamFuncs = std.StaticStringMap(void).initComptime(&.{
	.{"ip4_addr_string"},
});

test "trace_tool_fuzz" {
    const input = testing.fuzzInput(.{});
    const seed = std.hash.Wyhash.hash(testing.random_seed, input);
    const btf = libbpf.btf__load_vmlinux_btf().?;
    const i = seed % libbpf.btf__type_cnt(btf);
    const t: *const libbpf.btf_type = libbpf.btf__type_by_id(btf, @intCast(i));

    if (libbpf.btf_kind(t) == libbpf.BTF_KIND_FUNC) {
        const func_proto: *const libbpf.btf_type = libbpf.btf__type_by_id(btf, t.unnamed_0.type);
        const n = libbpf.BTF_INFO_VLEN(@as(c_int, @bitCast(func_proto.info)));
        const name = std.mem.span(libbpf.btf__name_by_offset(btf, t.name_off));

        if (structParamFuncs.has(name)) return error.SkipZigTest;

        var buf: [256]u8 = undefined;
        const specifier = try std.fmt.bufPrintZ(&buf, "-Dkprobe={s[name]}:{s[arg0]}{s[arg1]}{s[arg2]}{s[arg3]}{s[arg4]}{s[ret]}", .{
            .name = name,
            .arg0 = if (n > 0) "arg0" else "",
            .arg1 = if (n > 1) ",arg1" else "",
            .arg2 = if (n > 2) ",arg2" else "",
            .arg3 = if (n > 3) ",arg3" else "",
            .arg4 = if (n > 4) ",arg4" else "",
            .ret = if (func_proto.unnamed_0.type != 0) ",ret" else "",
        });
        const result = try std.process.Child.run(.{ .allocator = allocator, .argv = &.{ build_options.zig_exe, "build", "_trace", specifier } });
        const rc = result.term.Exited;

        if (rc != 0) {
            print("\nspecifier: {s}\n", .{specifier});
            print("stdout:\n{s}\n", .{result.stdout});
            print("stderr:\n{s}\n", .{result.stderr});
        }
        try testing.expectEqual(0, rc);
    } else return error.SkipZigTest;
}
