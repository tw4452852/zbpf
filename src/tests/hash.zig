const std = @import("std");
const root = @import("root.zig");
const print = std.debug.print;
const testing = std.testing;
const allocator = root.allocator;
const libbpf = root.libbpf;

test "hash" {
    const bytes = @embedFile("@hash");

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

        // map[0] = 1
        var k: u32 = 0;
        var v: u32 = 1;
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

        // expect map[0] not existing
        k = 0;
        ret = libbpf.bpf_map__lookup_elem(map, &k, @sizeOf(@TypeOf(k)), &v, @sizeOf(@TypeOf(v)), 0);
        try testing.expect(ret != 0);

        // expect map[1] == 2
        k = 1;
        ret = libbpf.bpf_map__lookup_elem(map, &k, @sizeOf(@TypeOf(k)), &v, @sizeOf(@TypeOf(v)), 0);
        if (ret != 0) {
            print("failed loopup map element: {}\n", .{std.posix.errno(-1)});
            return error.MAP_LOOKUP;
        }

        try testing.expectEqual(@as(@TypeOf(v), 2), v);
    }
}
