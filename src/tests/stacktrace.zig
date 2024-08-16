const std = @import("std");
const root = @import("root.zig");
const print = std.debug.print;
const testing = std.testing;
const allocator = root.allocator;
const libbpf = root.libbpf;

const STACK_TRACE = [127]u64;

test "stacktrace" {
    const bytes = @embedFile("@stacktrace");

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
        const stackmap = libbpf.bpf_object__find_map_by_name(obj, "stackmap").?;
        const astackmap = libbpf.bpf_object__find_map_by_name(obj, "astackmap").?;
        const indexmap = libbpf.bpf_object__find_map_by_name(obj, "indexmap").?;

        const zero: u32 = 0;
        var index: i32 = -1;
        ret = libbpf.bpf_map__update_elem(indexmap, &zero, @sizeOf(u32), &index, @sizeOf(@TypeOf(index)), 0);
        if (ret != 0) {
            print("failed update index element: {}\n", .{std.posix.errno(-1)});
            return error.MAP_UPDATE;
        }

        const link = libbpf.bpf_program__attach(prog) orelse {
            print("failed to attach prog {s}: {}\n", .{ libbpf.bpf_program__name(prog), std.posix.errno(-1) });
            return error.ATTACH;
        };
        defer _ = libbpf.bpf_link__destroy(link);

        std.time.sleep(10);

        var v: STACK_TRACE = undefined;
        var av: STACK_TRACE = undefined;

        ret = libbpf.bpf_map__lookup_elem(indexmap, &zero, @sizeOf(u32), &index, @sizeOf(@TypeOf(index)), 0);
        if (ret != 0) {
            print("failed lookup stackmap element: {}\n", .{std.posix.errno(-1)});
            return error.MAP_LOOKUP;
        }
        ret = libbpf.bpf_map__lookup_elem(stackmap, &index, @sizeOf(u32), &v, @sizeOf(@TypeOf(v)), 0);
        if (ret != 0) {
            print("failed lookup stackmap element: {}\n", .{std.posix.errno(-1)});
            return error.MAP_LOOKUP;
        }
        ret = libbpf.bpf_map__lookup_elem(astackmap, &zero, @sizeOf(u32), &av, @sizeOf(@TypeOf(av)), 0);
        if (ret != 0) {
            print("failed lookup astackmap element: {}\n", .{std.posix.errno(-1)});
            return error.MAP_LOOKUP;
        }

        try testing.expect(v[0] != 0);
        try testing.expectEqual(v, av);
    }
}
