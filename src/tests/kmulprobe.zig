const std = @import("std");
const root = @import("root.zig");
const print = std.debug.print;
const testing = std.testing;
const allocator = root.allocator;
const libbpf = root.libbpf;
const REGS = @import("bpf").Args.REGS;

test "kmulprobe" {
    if (!root.btf_name_exist("bpf_kprobe_multi_link")) return error.SkipZigTest;

    _ = libbpf.libbpf_set_print(root.dbg_printf);

    const path = try allocator.dupeZ(u8, @import("@build_options").prog_kmulprobe_path);
    defer allocator.free(path);
    const obj = libbpf.bpf_object__open(path);
    if (obj == null) {
        print("failed to open bpf object: {}\n", .{std.posix.errno(-1)});
        return error.OPEN;
    }
    defer libbpf.bpf_object__close(obj);

    const ret = libbpf.bpf_object__load(obj);
    if (ret != 0) {
        print("failed to load bpf object: {}\n", .{std.posix.errno(-1)});
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
        print("failed to attach entry_prog {s}: {}\n", .{ libbpf.bpf_program__name(entry_prog), std.posix.errno(-1) });
        return error.ATTACH;
    };
    defer _ = libbpf.bpf_link__destroy(entry_link);

    opt.retprobe = true;
    const exit_link = libbpf.bpf_program__attach_kprobe_multi_opts(exit_prog, null, @ptrCast(&opt)) orelse {
        print("failed to attach prog {s}: {}\n", .{ libbpf.bpf_program__name(exit_prog), std.posix.errno(-1) });
        return error.ATTACH;
    };
    defer _ = libbpf.bpf_link__destroy(exit_link);

    // setup events ring buffer
    const events = libbpf.bpf_object__find_map_by_name(obj, "events").?;
    var ctx = Ctx{
        .seen = 0,
        .arg2 = 0,
        .ret = 0,
    };
    const ring_buf = libbpf.ring_buffer__new(libbpf.bpf_map__fd(events), on_sample, &ctx, null).?;
    defer libbpf.ring_buffer__free(ring_buf);

    const expected_count = syms.len;
    // trigger kprobes
    var buf: [64]u8 = undefined;
    var sx = std.mem.zeroes(std.os.linux.Statx);
    var expect_ret: i32 = @truncate(@as(isize, @bitCast(std.os.linux.listxattr("/nonexist", &buf, buf.len))));
    expect_ret +%= @truncate(@as(isize, @bitCast(std.os.linux.statx(0, "/noexist", 0, 0, &sx))));
    const expect_arg2: i32 = buf.len + 0;

    const n = libbpf.ring_buffer__consume(ring_buf);
    if (n != expected_count) {
        print("failed consume ring buffer: return {}, expect {}, err:{}\n", .{ n, expected_count, std.posix.errno(-1) });
        return error.PERF_BUF;
    }

    try testing.expectEqual(@as(@TypeOf(ctx.seen), @intCast(expected_count)), ctx.seen);
    try testing.expectEqual(expect_ret, ctx.ret);
    try testing.expectEqual(expect_arg2, ctx.arg2);
}

const Ctx = extern struct {
    seen: u32,
    ret: i32,
    arg2: i32,
};

fn on_sample(_ctx: ?*anyopaque, _data: ?*anyopaque, _: usize) callconv(.c) c_int {
    var ctx: *Ctx = @ptrCast(@alignCast(_ctx.?));
    const args: *REGS = @alignCast(@ptrCast(_data.?));

    ctx.seen += 1;
    ctx.ret +%= @truncate(@as(isize, @bitCast(args.ret_ptr().*)));
    ctx.arg2 +%= @truncate(@as(isize, @bitCast(args.arg2_ptr().*)));
    return 0;
}
