const std = @import("std");
const root = @import("root.zig");
const print = std.debug.print;
const testing = std.testing;
const allocator = root.allocator;
const libbpf = root.libbpf;

test "fentry" {
    const obj_bytes = @embedFile("@fentry");
    const bytes = try allocator.dupe(u8, obj_bytes);
    defer allocator.free(bytes);

    _ = libbpf.libbpf_set_print(root.dbg_printf);

    const obj = libbpf.bpf_object__open_mem(bytes.ptr, bytes.len, null);
    if (obj == null) {
        print("failed to open bpf object: {}\n", .{std.os.errno(-1)});
        return error.OPEN;
    }
    defer libbpf.bpf_object__close(obj);

    var ret = libbpf.bpf_object__load(obj);
    if (ret != 0) {
        print("failed to load bpf object: {}\n", .{std.os.errno(-1)});
        return error.LOAD;
    }

    const entry_prog = libbpf.bpf_object__find_program_by_name(obj, "test_fentry").?;
    const exit_prog = libbpf.bpf_object__find_program_by_name(obj, "test_fexit").?;

    const arg2 = libbpf.bpf_object__find_map_by_name(obj, "entry").?;
    const rc = libbpf.bpf_object__find_map_by_name(obj, "exit").?;

    const entry_link = libbpf.bpf_program__attach(entry_prog) orelse {
        const errno = std.os.errno(-1);
        print("failed to attach entry_prog {s}: {}\n", .{ libbpf.bpf_program__name(entry_prog), errno });

        const ENOTSUPP = 524;
        if (@enumToInt(errno) == ENOTSUPP) return error.SkipZigTest;
        return error.ATTACH;
    };
    defer _ = libbpf.bpf_link__destroy(entry_link);
    const exit_link = libbpf.bpf_program__attach(exit_prog) orelse {
        print("failed to attach prog {s}: {}\n", .{ libbpf.bpf_program__name(exit_prog), std.os.errno(-1) });
        return error.ATTACH;
    };
    defer _ = libbpf.bpf_link__destroy(exit_link);

    var buf: [64]u8 = undefined;
    const n = std.os.linux.listxattr("/nonexist", &buf, buf.len);

    const k: u32 = 0;
    var arg2_got: usize = undefined;
    ret = libbpf.bpf_map__lookup_elem(arg2, &k, @sizeOf(@TypeOf(k)), &arg2_got, @sizeOf(@TypeOf(arg2_got)), 0);
    if (ret != 0) {
        print("failed loopup map element: {}\n", .{std.os.errno(-1)});
        return error.MAP_LOOKUP;
    }
    var rc_got: usize = undefined;
    ret = libbpf.bpf_map__lookup_elem(rc, &k, @sizeOf(@TypeOf(k)), &rc_got, @sizeOf(@TypeOf(rc_got)), 0);
    if (ret != 0) {
        print("failed loopup map element: {}\n", .{std.os.errno(-1)});
        return error.MAP_LOOKUP;
    }
    try testing.expectEqual(buf.len, arg2_got);
    try testing.expectEqual(n, rc_got);
}
