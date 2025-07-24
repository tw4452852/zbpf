const std = @import("std");
const root = @import("root.zig");
const print = std.debug.print;
const testing = std.testing;
const allocator = root.allocator;
const libbpf = root.libbpf;

test "ksyscall" {
    _ = libbpf.libbpf_set_print(root.dbg_printf);

    const path = try allocator.dupeZ(u8, @import("@build_options").prog_ksyscall_path);
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

    const entry_prog = libbpf.bpf_object__find_program_by_name(obj, "test_ksyscall").?;
    const exit_prog = libbpf.bpf_object__find_program_by_name(obj, "test_kretsyscall").?;

    const entry = libbpf.bpf_object__find_map_by_name(obj, "entry").?;
    const exit = libbpf.bpf_object__find_map_by_name(obj, "exit").?;

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

    var buf: [64]u8 = undefined;
    const arg0 = "arg1";
    const arg1 = "arg2";
    const n = std.os.linux.getxattr(
        arg0,
        arg1,
        &buf,
        buf.len,
    );

    const k: u32 = 0;
    var got_entry: u64 = undefined;
    ret = libbpf.bpf_map__lookup_elem(entry, &k, @sizeOf(@TypeOf(k)), &got_entry, @sizeOf(@TypeOf(got_entry)), 0);
    if (ret != 0) {
        print("failed loopup map element: {}\n", .{std.posix.errno(-1)});
        return error.MAP_LOOKUP;
    }
    var got_exit: isize = undefined;
    ret = libbpf.bpf_map__lookup_elem(exit, &k, @sizeOf(@TypeOf(k)), &got_exit, @sizeOf(@TypeOf(got_exit)), 0);
    if (ret != 0) {
        print("failed loopup map element: {}\n", .{std.posix.errno(-1)});
        return error.MAP_LOOKUP;
    }

    try testing.expectEqual(@intFromPtr(arg0.ptr) + @intFromPtr(arg1.ptr) + @intFromPtr(&buf) + buf.len, got_entry);
    try testing.expectEqual(@as(isize, @bitCast(n)), got_exit);
}
