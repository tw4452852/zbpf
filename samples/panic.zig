const std = @import("std");
const bpf = @import("bpf");

pub const panic = bpf.panic; // register panic handler

export fn test_panic(ctx: bool) linksection("xdp") c_long {
    if (ctx) @panic("test");
    return 0;
}
