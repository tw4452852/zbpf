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

test "xdp_ping" {
    _ = libbpf.libbpf_set_print(root.dbg_printf);

    const path = try allocator.dupeZ(u8, @import("@build_options").prog_xdp_ping_path);
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

    const prog = libbpf.bpf_object__find_program_by_name(obj, "xdp_ping").?;
    const ipv4 = libbpf.bpf_object__find_map_by_name(obj, "ipv4").?;
    const ipv6 = libbpf.bpf_object__find_map_by_name(obj, "ipv6").?;

    const idx = c.if_nametoindex("lo");
    if (idx == 0) {
        print("failed to get index of lo: {}\n", .{std.posix.errno(-1)});
        return error.DEV;
    }

    const prog_fd = libbpf.bpf_program__fd(prog);
    ret = libbpf.bpf_xdp_attach(@intCast(idx), prog_fd, c.XDP_FLAGS_UPDATE_IF_NOEXIST, null);
    if (ret < 0) {
        print("failed to attach program: {}\n", .{std.posix.errno(-1)});
        return error.ATTACH;
    }
    defer _ = libbpf.bpf_xdp_detach(@intCast(idx), c.XDP_FLAGS_UPDATE_IF_NOEXIST, null);

    const expected: u32 = @as(*const u32, @ptrCast(@alignCast("ipv4"))).*;
    const expected6: u32 = @as(*const u32, @ptrCast(@alignCast("ipv6"))).*;

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
