const std = @import("std");
const root = @import("root.zig");
const print = std.debug.print;
const testing = std.testing;
const allocator = root.allocator;
const libbpf = root.libbpf;

test "ringbuf" {
    const bytes = @embedFile("@ringbuf");

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
        const my_pid = libbpf.bpf_object__find_map_by_name(obj, "my_pid").?;
        // map[0] = current pid
        const k: u32 = 0;
        const v: u32 = std.Thread.getCurrentId();
        ret = libbpf.bpf_map__update_elem(my_pid, &k, @sizeOf(@TypeOf(k)), &v, @sizeOf(@TypeOf(v)), 0);
        if (ret != 0) {
            print("failed update map element: {}\n", .{std.posix.errno(-1)});
            return error.MAP_UPDATE;
        }

        const link = libbpf.bpf_program__attach(prog) orelse {
            print("failed to attach prog {s}: {}\n", .{ libbpf.bpf_program__name(prog), std.posix.errno(-1) });
            return error.ATTACH;
        };
        defer _ = libbpf.bpf_link__destroy(link);

        // setup events ring buffer
        const events = libbpf.bpf_object__find_map_by_name(obj, "events").?;
        var got = std.ArrayList(u8).init(allocator);
        defer got.deinit();
        var ctx = Ctx{
            .seen = 0,
            .got = &got,
        };
        const ring_buf = libbpf.ring_buffer__new(libbpf.bpf_map__fd(events), on_sample, &ctx, null).?;
        defer libbpf.ring_buffer__free(ring_buf);

        const expected_count = 3;
        const expected_str = "1" ** expected_count;
        for (0..expected_count) |_| {
            std.time.sleep(11);
        }

        const n = libbpf.ring_buffer__consume(ring_buf);
        if (n != expected_count) {
            print("failed consume ring buffer: return {}, expect {}, err:{}\n", .{ n, expected_count, std.posix.errno(-1) });
            return error.PERF_BUF;
        }

        try testing.expectEqual(@as(@TypeOf(ctx.seen), @intCast(expected_count)), ctx.seen);
        try testing.expectEqualStrings(expected_str, got.items);
    }
}

const Ctx = extern struct {
    seen: u32,
    got: *std.ArrayList(u8),
};

fn on_sample(_ctx: ?*anyopaque, _data: ?*anyopaque, _: usize) callconv(.C) c_int {
    var ctx: *Ctx = @ptrCast(@alignCast(_ctx.?));
    const c: *const u8 = @ptrCast(_data.?);

    ctx.seen += 1;
    ctx.got.append(c.*) catch unreachable;
    return 0;
}
