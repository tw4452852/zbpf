const std = @import("std");
const root = @import("root.zig");
const print = std.debug.print;
const testing = std.testing;
const allocator = root.allocator;
const libbpf = root.libbpf;

test "tracepoint" {
    const obj_bytes = @embedFile("@tracepoint");
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

    if (libbpf.bpf_object__next_program(obj, null)) |prog| {
        var map = libbpf.bpf_object__next_map(obj, null).?;
        print("find prog: {s}, map: {s}\n", .{ libbpf.bpf_program__name(prog), libbpf.bpf_map__name(map) });

        const link = libbpf.bpf_program__attach(prog) orelse {
            print("failed to attach prog {s}: {}\n", .{ libbpf.bpf_program__name(prog), std.os.errno(-1) });
            return error.ATTACH;
        };
        defer _ = libbpf.bpf_link__detach(link);

        std.time.sleep(10);

        // expect map[0] > 1
        const k: u32 = 0;
        var v: u32 = undefined;
        ret = libbpf.bpf_map__lookup_elem(map, &k, @sizeOf(@TypeOf(k)), &v, @sizeOf(@TypeOf(v)), 0);
        if (ret != 0) {
            print("failed loopup map element: {}\n", .{std.os.errno(-1)});
            return error.MAP_LOOKUP;
        }

        try testing.expect(v > 1);
    }
}
