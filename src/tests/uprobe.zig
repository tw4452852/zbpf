const std = @import("std");
const root = @import("root.zig");
const print = std.debug.print;
const testing = std.testing;
const allocator = root.allocator;
const libbpf = root.libbpf;

export fn test_func(arg0: u64) u64 {
    return arg0;
}

test "uprobe" {
    _ = libbpf.libbpf_set_print(root.dbg_printf);

    const path = try allocator.dupeZ(u8, @import("@build_options").prog_uprobe_path);
    defer allocator.free(path);
    const obj = libbpf.bpf_object__open(path);
    if (obj == null) {
        print("failed to open bpf object: {}\n", .{std.posix.errno(-1)});
        return error.OPEN;
    }
    defer libbpf.bpf_object__close(obj);

    var ret = libbpf.bpf_object__load(obj);
    if (ret != 0) {
        print("failed to load bpf object: {}\n", .{std.posix.errno(-1)});
        return error.LOAD;
    }

    const entry_prog = libbpf.bpf_object__find_program_by_name(obj, "test_uprobe").?;
    const exit_prog = libbpf.bpf_object__find_program_by_name(obj, "test_uretprobe").?;

    const arg = libbpf.bpf_object__find_map_by_name(obj, "entry").?;
    const rc = libbpf.bpf_object__find_map_by_name(obj, "exit").?;

    const entry_link = libbpf.bpf_program__attach(entry_prog) orelse {
        print("failed to attach entry_prog {s}: {}\n", .{ libbpf.bpf_program__name(entry_prog), std.posix.errno(-1) });
        return error.ATTACH;
    };
    defer _ = libbpf.bpf_link__destroy(entry_link);
    const exit_link = libbpf.bpf_program__attach(exit_prog) orelse {
        print("failed to attach prog {s}: {}\n", .{ libbpf.bpf_program__name(exit_prog), std.posix.errno(-1) });
        return error.ATTACH;
    };
    defer _ = libbpf.bpf_link__destroy(exit_link);

    const expected_arg: u64 = 0xabcd;
    const expected_ret: u64 = test_func(expected_arg);

    const k: u32 = 0;
    var got_arg: u64 = undefined;
    ret = libbpf.bpf_map__lookup_elem(arg, &k, @sizeOf(@TypeOf(k)), &got_arg, @sizeOf(@TypeOf(got_arg)), 0);
    if (ret != 0) {
        print("failed loopup map element: {}\n", .{std.posix.errno(-1)});
        return error.MAP_LOOKUP;
    }
    var got_ret: u64 = undefined;
    ret = libbpf.bpf_map__lookup_elem(rc, &k, @sizeOf(@TypeOf(k)), &got_ret, @sizeOf(@TypeOf(got_ret)), 0);
    if (ret != 0) {
        print("failed loopup map element: {}\n", .{std.posix.errno(-1)});
        return error.MAP_LOOKUP;
    }

    try testing.expectEqual(expected_arg, got_arg);
    try testing.expectEqual(expected_ret, got_ret);
}
