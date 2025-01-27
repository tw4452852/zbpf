const std = @import("std");
const BPF = std.os.linux.BPF;
const helpers = BPF.kern.helpers;

const bpf = @import("bpf");
const Tc = bpf.Tc;

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

export fn tc_ingress(ctx: *Tc.SkBuff) linksection("tc") c_int {
    const proto_ip4 = 0x0800;
    const proto_ip6 = 0x86DD;

    switch (ctx.protocol) {
        std.mem.nativeTo(u16, proto_ip4, .big) => handle_ipv4(ctx),
        std.mem.nativeTo(u16, proto_ip6, .big) => handle_ipv6(ctx),
        else => {},
    }

    return @intFromEnum(Tc.RET.ok);
}

fn handle_ipv4(ctx: *Tc.SkBuff) void {
    const iphdr_offset = @sizeOf(EthHdr);
    const hdr: *const IPv4Hdr = ctx.get_ptr(IPv4Hdr, iphdr_offset) orelse return;
    const fmt = "Got IPv4 packet: proto: %d, tot_len: %d, ttl: %d";
    _ = helpers.trace_printk(fmt, fmt.len + 1, hdr.proto, hdr.tot_len, hdr.ttl);

    const IPPROTO_ICMP = 1;
    if (hdr.proto == IPPROTO_ICMP) {
        const payload: *const u32 = ctx.get_ptr(u32, iphdr_offset + @sizeOf(IPv4Hdr) + @sizeOf(IcmpEchoHdr)) orelse return;

        ipv4.update(.any, 0, std.mem.toNative(u32, payload.*, .big));
    }
}

fn handle_ipv6(ctx: *Tc.SkBuff) void {
    const iphdr_offset = @sizeOf(EthHdr);
    const hdr: *const IPv6Hdr = ctx.get_ptr(IPv6Hdr, iphdr_offset) orelse return;
    const fmt = "Got IPv6 packet: nxt: %d, plen: %d, hlim: %d";
    _ = helpers.trace_printk(fmt, fmt.len + 1, hdr.nxt, hdr.plen, hdr.hlim);

    const IPPROTO_ICMPV6 = 58;
    if (hdr.nxt == IPPROTO_ICMPV6) {
        const payload: *const u32 = ctx.get_ptr(u32, iphdr_offset + @sizeOf(IPv6Hdr) + @sizeOf(IcmpEchoHdr)) orelse return;

        ipv6.update(.any, 0, std.mem.toNative(u32, payload.*, .big));
    }
}
