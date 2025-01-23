const std = @import("std");
const print = std.debug.print;
const testing = std.testing;

const root = @import("root.zig");
const allocator = root.allocator;
const libbpf = root.libbpf;

const c = @cImport({
    @cInclude("net/if.h");
    @cInclude("linux/if_link.h");
});

// Since Zig translate-c doesn't support bitfields, it translates them to opaque types.
// The struct are actually not really bitfields, they only have a last field `size_t :0;` which is a zero-width bitfield, used to add alignment between bitfields.
// The layout *should* thus be the same as a regular struct.
// https://github.com/libbpf/libbpf/blob/324f3c3846d99c8a1e1384a55591f893f0ae5de4/src/libbpf.h#L1282
pub const Hook = extern struct {
    sz: usize,
    ifindex: c_int,
    attach_point: c_int,
    parent: u32,
};

pub const Opts = extern struct {
    sz: usize,
    prog_fd: c_int,
    flags: u32,
    prog_id: u32,
    handle: u32,
    priority: u32,
};

const EEXIST: c_int = @intFromEnum(std.c.E.EXIST);

// https://patchwork.kernel.org/project/netdevbpf/patch/20210512103451.989420-3-memxor@gmail.com/
test "tc_ingress" {
    const bytes = @embedFile("@tc_ingress");

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

    const prog = libbpf.bpf_object__find_program_by_name(obj, "tc_ingress").?;
    const ipv4 = libbpf.bpf_object__find_map_by_name(obj, "ipv4").?;
    const ipv6 = libbpf.bpf_object__find_map_by_name(obj, "ipv6").?;

    const idx = c.if_nametoindex("lo");
    if (idx == 0) {
        print("failed to get index of lo: {}\n", .{std.posix.errno(-1)});
        return error.DEV;
    }

    const prog_fd = libbpf.bpf_program__fd(prog);
    var hook: Hook = std.mem.zeroes(Hook);
    hook.sz = @sizeOf(Hook);
    hook.ifindex = @intCast(idx);
    hook.attach_point = libbpf.BPF_TC_INGRESS;

    // https://github.com/libbpf/libbpf/blob/324f3c3846d99c8a1e1384a55591f893f0ae5de4/src/netlink.c#L616
    // If there is already a qdisc hook on the interface, it will return -EEXIST.
    // We can ignore this error and continue to attach the program to the existing hook.
    ret = libbpf.bpf_tc_hook_create(@alignCast(@ptrCast(&hook)));
    if (ret < 0) {
        if (ret == -EEXIST) {
            print("there's already a qdisc hook on the interface, attaching to it...\n", .{});
        } else {
            print("failed to create hook: {}\n", .{std.posix.errno(-1)});
            return error.CREATE_HOOK;
        }
    }

    var opts: Opts = std.mem.zeroes(Opts);
    opts.sz = @sizeOf(Opts);
    opts.prog_fd = prog_fd;

    ret = libbpf.bpf_tc_attach(@ptrCast(&hook), @ptrCast(&opts));
    if (ret < 0) {
        print("failed to attach program: {}\n", .{std.posix.errno(-1)});
        return error.ATTACH;
    }

    print("Handle: {}\n", .{opts.handle});
    print("Priority: {}\n", .{opts.priority});

    defer {
        opts.prog_id = 0;
        opts.prog_fd = 0;
        ret = libbpf.bpf_tc_detach(@ptrCast(&hook), @ptrCast(&opts));
        if (ret < 0) {
            print("failed to detach program: {}\n", .{std.posix.errno(-1)});
        }
    }

    const expected: u32 = @as(*const u32, @alignCast(@ptrCast("ipv4"))).*;
    const expected6: u32 = @as(*const u32, @alignCast(@ptrCast("ipv6"))).*;

    var buf: [16]u8 = undefined;
    const pattern = try std.fmt.bufPrint(&buf, "{x}", .{expected});
    var result = try std.process.Child.run(.{ .allocator = allocator, .argv = &.{ "ping", "-4", "-c", "1", "-p", pattern, "-s", "4", "localhost" } });
    if (testing.expect(result.term.Exited == 0)) |_| {
        allocator.free(result.stdout);
        allocator.free(result.stderr);
    } else |err| {
        print("{s}\n{s}\n", .{ result.stdout, result.stderr });
        allocator.free(result.stdout);
        allocator.free(result.stderr);
        return err;
    }

    const pattern6 = try std.fmt.bufPrint(&buf, "{x}", .{expected6});
    result = try std.process.Child.run(.{ .allocator = allocator, .argv = &.{ "ping", "-6", "-c", "1", "-p", pattern6, "-s", "4", "::1" } });
    if (testing.expect(result.term.Exited == 0)) |_| {
        allocator.free(result.stdout);
        allocator.free(result.stderr);
    } else |err| {
        print("{s}\n{s}\n", .{ result.stdout, result.stderr });
        allocator.free(result.stdout);
        allocator.free(result.stderr);
        return err;
    }

    var k: u32 = 0;
    var v: u32 = undefined;
    ret = libbpf.bpf_map__lookup_elem(ipv4, &k, @sizeOf(@TypeOf(k)), &v, @sizeOf(@TypeOf(v)), 0);
    try testing.expectEqual(expected, v);

    ret = libbpf.bpf_map__lookup_elem(ipv6, &k, @sizeOf(@TypeOf(k)), &v, @sizeOf(@TypeOf(v)), 0);
    try testing.expectEqual(expected6, v);
}
