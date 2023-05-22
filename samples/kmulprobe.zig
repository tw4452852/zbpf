const std = @import("std");
const bpf = @import("bpf");

var count = bpf.Map.ArrayMap("count", u64, 1, 0).init();

fn count_add() void {
    const n = count.lookup(0) orelse return;
    count.update(.any, 0, n.* + 1) catch return;
}

export fn test_kmulprobe() linksection("kprobe.multi") callconv(.C) c_long {
    count_add();
    return 0;
}

export fn test_kmulretprobe() linksection("kretprobe.multi") callconv(.C) c_long {
    count_add();
    return 0;
}
