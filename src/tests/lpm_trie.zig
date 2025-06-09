const std = @import("std");
const root = @import("root.zig");
const print = std.debug.print;
const testing = std.testing;
const allocator = root.allocator;
const libbpf = root.libbpf;

const Ipv4LpmKey = extern struct {
    prefixlen: u32,
    addr: u32,
};

test "lpm_trie" {
    const bytes = @embedFile("@lpm_trie");

    _ = libbpf.libbpf_set_print(root.dbg_printf);

    const obj = libbpf.bpf_object__open_mem(bytes.ptr, bytes.len, null);
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

    if (libbpf.bpf_object__next_program(obj, null)) |prog| {
        const map = libbpf.bpf_object__next_map(obj, null).?;

        var k = Ipv4LpmKey{
            .prefixlen = 32,
            .addr = 16777343, // 127.0.0.1
        };
        var v: u64 = 1;
        ret = libbpf.bpf_map__update_elem(map, &k, @sizeOf(@TypeOf(k)), &v, @sizeOf(@TypeOf(v)), 0);
        if (ret != 0) {
            print("failed update map element: {}\n", .{std.posix.errno(-1)});
            return error.MAP_UPDATE;
        }

        // run bpf program
        const fd = libbpf.bpf_program__fd(prog);
        var buf: [32]u8 = undefined;

        var attr = std.mem.zeroInit(libbpf.bpf_test_run_opts, .{
            .sz = @sizeOf(libbpf.bpf_test_run_opts),
            .data_in = &buf,
            .data_size_in = 32,
            .data_out = &buf,
        });
        ret = libbpf.bpf_prog_test_run_opts(fd, &attr);
        if (ret != 0) {
            print("failed run prog: {}\n", .{std.posix.errno(-1)});
            return error.RUN;
        }
        try testing.expectEqual(@as(@TypeOf(attr.retval), 0), attr.retval);

        // expect 127.0.0.1/32 not existing
        k.addr = 16777343;
        ret = libbpf.bpf_map__lookup_elem(map, &k, @sizeOf(@TypeOf(k)), &v, @sizeOf(@TypeOf(v)), 0);
        try testing.expect(ret != 0);

        // expect 127.0.0.3/32 == 2
        k.addr = 50331775;
        ret = libbpf.bpf_map__lookup_elem(map, &k, @sizeOf(@TypeOf(k)), &v, @sizeOf(@TypeOf(v)), 0);
        if (ret != 0) {
            print("failed loopup map element: {}\n", .{std.posix.errno(-1)});
            return error.MAP_LOOKUP;
        }

        try testing.expectEqual(@as(@TypeOf(v), 2), v);
    }
}
