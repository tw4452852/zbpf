const std = @import("std");
const bpf = @import("bpf");
const Xdp = bpf.Xdp;
const BPF = std.os.linux.BPF;
const helpers = BPF.kern.helpers;

var ipv4 = bpf.Map.HashMap("ipv4", u32, u32, 1, 0).init();
var ipv6 = bpf.Map.HashMap("ipv6", u32, u32, 1, 0).init();

const EthHdr = extern struct {
    dest: [6]u8,
    src: [6]u8,
    proto: u16,
};

const IcmpEchoHdr = extern struct {
    typ: u8,
    code: u8,
    checksum: u16,
    id: u16,
    seq: u16,
};

const IPv6Hdr = extern struct {
    flow: u32,
    plen: u16,
    nxt: u8,
    hlim: u8,
    src: [16]u8,
    dst: [16]u8,
};

const IPv4Hdr = extern struct {
    ver_ihl: u8,
    tos: u8,
    tot_len: u16,
    id: u16,
    frag_off: u16,
    ttl: u8,
    proto: u8,
    check: u16,
    src: u32,
    dst: u32,
};

export fn xdp_ping(ctx: *Xdp.Meta) linksection("xdp") c_int {
    const data = ctx.data();

    if (data.len > @sizeOf(EthHdr)) {
        const eth_hdr: *const EthHdr = @alignCast(@ptrCast(data.ptr));
        const proto_ip4 = 0x0800;
        const proto_ip6 = 0x86DD;
        var proto: u16 = undefined;
        _ = helpers.probe_read_kernel(&proto, @sizeOf(u16), &eth_hdr.proto);

        switch (proto) {
            std.mem.nativeTo(u16, proto_ip4, .big) => handle_ipv4(data[@sizeOf(EthHdr)..]),
            std.mem.nativeTo(u16, proto_ip6, .big) => handle_ipv6(data[@sizeOf(EthHdr)..]),
            else => {},
        }
    }
    return @intFromEnum(Xdp.RET.pass);
}

fn handle_ipv4(data: []const u8) void {
    const hdr: *const IPv4Hdr = @alignCast(@ptrCast(data));
    var proto: u8 = undefined;
    _ = helpers.probe_read_kernel(&proto, @sizeOf(u8), &hdr.proto);
    const IPPROTO_ICMP = 1;
    if (proto == IPPROTO_ICMP) {
        const payload: *const u32 = @alignCast(@ptrCast(data[@sizeOf(IPv4Hdr) + @sizeOf(IcmpEchoHdr) ..]));
        var v: u32 = undefined;
        _ = helpers.probe_read_kernel(&v, @sizeOf(u32), payload);

        ipv4.update(.any, 0, std.mem.toNative(u32, v, .big)) catch {};
    }
}

fn handle_ipv6(data: []const u8) void {
    const hdr: *const IPv6Hdr = @alignCast(@ptrCast(data.ptr));
    var proto: u8 = undefined;
    _ = helpers.probe_read_kernel(&proto, @sizeOf(u8), &hdr.nxt);
    const IPPROTO_ICMPV6 = 58;
    if (proto == IPPROTO_ICMPV6) {
        const payload: *const u32 = @alignCast(@ptrCast(data[@sizeOf(IPv6Hdr) + @sizeOf(IcmpEchoHdr) ..]));
        var v: u32 = undefined;
        _ = helpers.probe_read_kernel(&v, @sizeOf(u32), payload);

        ipv6.update(.any, 0, std.mem.toNative(u32, v, .big)) catch {};
    }
}
