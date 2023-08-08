const std = @import("std");
const root = @import("root.zig");
const print = std.debug.print;
const testing = std.testing;
const allocator = root.allocator;
const libbpf = root.libbpf;

test "kmulprobe" {
    if (!root.btf_name_exist("bpf_kprobe_multi_link")) return error.SkipZigTest;

    const obj_bytes = @embedFile("@kmulprobe");
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

    const entry_prog = libbpf.bpf_object__find_program_by_name(obj, "test_kmulprobe").?;
    const exit_prog = libbpf.bpf_object__find_program_by_name(obj, "test_kmulretprobe").?;

    const KPROBE_MULTI_OPT = extern struct {
        sz: usize,
        syms: [*c][*c]const u8 = null,
        addrs: [*c]const c_ulong = null,
        cookies: [*c]const c_ulonglong = null,
        cnt: usize,
        retprobe: bool,
    };

    const syms = [_][*c]const u8{
        "path_listxattr",
        "do_statx",
    };

    var opt = KPROBE_MULTI_OPT{
        .sz = @sizeOf(KPROBE_MULTI_OPT),
        .syms = @constCast(&syms),
        .cnt = syms.len,
        .retprobe = false,
    };
    const entry_link = libbpf.bpf_program__attach_kprobe_multi_opts(entry_prog, null, @ptrCast(&opt)) orelse {
        print("failed to attach entry_prog {s}: {}\n", .{ libbpf.bpf_program__name(entry_prog), std.os.errno(-1) });
        return error.ATTACH;
    };
    defer _ = libbpf.bpf_link__destroy(entry_link);
    const exit_link = libbpf.bpf_program__attach_kprobe_multi_opts(exit_prog, null, @ptrCast(&opt)) orelse {
        print("failed to attach prog {s}: {}\n", .{ libbpf.bpf_program__name(exit_prog), std.os.errno(-1) });
        return error.ATTACH;
    };
    defer _ = libbpf.bpf_link__destroy(exit_link);

    // trigger kprobes
    var buf: [64]u8 = undefined;
    var sx = std.mem.zeroes(std.os.linux.Statx);
    _ = std.os.linux.listxattr("/nonexist", &buf, buf.len);
    _ = std.os.linux.statx(0, "/noexist", 0, 0, &sx);

    const k: u32 = 0;
    var got: u64 = undefined;
    const map = libbpf.bpf_object__find_map_by_name(obj, "count").?;
    ret = libbpf.bpf_map__lookup_elem(map, &k, @sizeOf(@TypeOf(k)), &got, @sizeOf(@TypeOf(got)), 0);
    if (ret != 0) {
        print("failed loopup map element: {}\n", .{std.os.errno(-1)});
        return error.MAP_LOOKUP;
    }

    try testing.expectEqual(syms.len * 2, got);
}
