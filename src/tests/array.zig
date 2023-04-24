const std = @import("std");
const root = @import("root.zig");
const print = std.debug.print;
const testing = std.testing;
const allocator = root.allocator;
const libbpf = root.libbpf;

test "array" {
    const obj_bytes = @embedFile("@array");

    _ = libbpf.libbpf_set_print(root.dbg_printf);

    const obj = libbpf.bpf_object__open_mem(obj_bytes.ptr, obj_bytes.len, null);
    if (obj == null) {
        print("failed to open bpf object: {}\n", .{std.os.errno(-1)});
        return error.OPEN;
    }
    defer libbpf.bpf_object__close(obj);

    var _map = libbpf.bpf_object__next_map(obj, null);
    while (_map) |map| : (_map = libbpf.bpf_object__next_map(obj, _map)) {
        print("find map: {s}\n", .{libbpf.bpf_map__name(map)});
    }

    var ret = libbpf.bpf_object__load(obj);
    if (ret != 0) {
        print("failed to load bpf object: {}\n", .{std.os.errno(-1)});
        return error.LOAD;
    }

    if (libbpf.bpf_object__next_program(obj, null)) |prog| {
        var map = libbpf.bpf_object__next_map(obj, null).?;
        print("find prog: {s}, map: {s}\n", .{ libbpf.bpf_program__name(prog), libbpf.bpf_map__name(map) });

        // map[0] = 1
        var k: u32 = 0;
        var v: u32 = 1;
        ret = libbpf.bpf_map__update_elem(map, &k, @sizeOf(@TypeOf(k)), &v, @sizeOf(@TypeOf(v)), 0);
        if (ret != 0) {
            print("failed update map element: {}\n", .{std.os.errno(-1)});
            return error.MAP_UPDATE;
        }

        // run bpf program
        const fd = libbpf.bpf_program__fd(prog);
        var attr = std.mem.zeroInit(libbpf.bpf_test_run_opts, .{
            .sz = @sizeOf(libbpf.bpf_test_run_opts),
        });
        ret = libbpf.bpf_prog_test_run_opts(fd, &attr);
        if (ret != 0) {
            print("failed run prog: {}\n", .{std.os.errno(-1)});
            return error.RUN;
        }
        try testing.expectEqual(@as(@TypeOf(attr.retval), 0), attr.retval);

        // expect map[1] == 2
        k = 1;
        ret = libbpf.bpf_map__lookup_elem(map, &k, @sizeOf(@TypeOf(k)), &v, @sizeOf(@TypeOf(v)), 0);
        if (ret != 0) {
            print("failed loopup map element: {}\n", .{std.os.errno(-1)});
            return error.MAP_LOOKUP;
        }

        try testing.expectEqual(@as(@TypeOf(v), 2), v);
    }
}
