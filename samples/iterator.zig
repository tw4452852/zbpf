const std = @import("std");
const bpf = @import("bpf");

var n: u64 = 0;
export fn test_iteractor(ctx: *bpf.Iterator.BPF_MAP) linksection("iter/bpf_map") c_int {
    if (ctx.map) |_| {
        n += 1;
        ctx.meta.write(std.mem.asBytes(&n)) catch return 1;
    }

    return 0;
}
