const std = @import("std");
const bpf = @import("bpf");

var count = bpf.Map.ArrayMap("count", i32, 1, 0).init();

var n: i32 = 0;

const tp = bpf.Tracepoint{
    .category = "sched",
    .name = "sched_switch",
};

export fn test_tracepoint(ctx: *tp.Ctx()) linksection(tp.section()) callconv(.C) c_int {
    n += ctx.prev_pid;
    count.update(.any, 0, n) catch return 1;
    return 0;
}
