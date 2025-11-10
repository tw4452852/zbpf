const std = @import("std");
const root = @import("root.zig");
const print = std.debug.print;
const testing = std.testing;
const allocator = root.allocator;
const libbpf = root.libbpf;

test "perf_event" {
    _ = libbpf.libbpf_set_print(root.dbg_printf);

    const path = try allocator.dupeZ(u8, @import("@build_options").prog_perf_event_path);
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

        // setup events perf buffer
        const events = libbpf.bpf_object__find_map_by_name(obj, "events").?;
        var got: std.ArrayList(u8) = .empty;
        defer got.deinit(allocator);
        var ctx = Ctx{
            .seen = 0,
            .got = &got,
        };
        const perf_buf = libbpf.perf_buffer__new(libbpf.bpf_map__fd(events), 2, on_sample, null, &ctx, null).?;
        defer libbpf.perf_buffer__free(perf_buf);

        const expected_count = 3;
        const expected_str = "hello" ** expected_count;
        for (0..expected_count) |_| {
            try std.Io.Clock.Duration.sleep(.{ .clock = .awake, .raw = .fromNanoseconds(11) }, testing.io);
        }

        ret = libbpf.perf_buffer__consume(perf_buf);
        if (ret != 0) {
            print("failed consume perf buffer: {}\n", .{std.posix.errno(-1)});
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

fn on_sample(_ctx: ?*anyopaque, _: c_int, data: ?*anyopaque, _: u32) callconv(.c) void {
    var ctx: *Ctx = @ptrCast(@alignCast(_ctx.?));
    const s = std.mem.sliceTo(@as([*c]const u8, @ptrCast(data)), 0);

    ctx.seen += 1;
    ctx.got.appendSlice(allocator, s) catch unreachable;
}
