const std = @import("std");
const bpf = @import("bpf");
const vmlinux = @import("vmlinux");
const get_stack = std.os.linux.BPF.kern.helpers.get_stack;

var indexmap = bpf.Map.ArrayMap("indexmap", i32, 1, 0).init();
var stackmap = bpf.Map.StackTraceMap("stackmap", 16).init();
var astackmap = bpf.Map.ArrayMap("astackmap", bpf.Map.STACK_TRACE, 1, 0).init();

const tp = bpf.Tracepoint{
    .category = "sched",
    .name = "sched_switch",
};

export fn test_stacktrace(ctx: *tp.Ctx()) linksection(tp.section()) callconv(.C) c_int {
    if (indexmap.lookup(0)) |i| {
        if (i.* < 0) {
            const index = stackmap.get_current_stack(ctx, 0);
            i.* = @intCast(index);
            if (astackmap.lookup(0)) |p| {
                _ = get_stack(ctx, p, @sizeOf(bpf.Map.STACK_TRACE), 0);
            } else bpf.exit(@src(), @as(c_long, 1));
        }
    } else bpf.exit(@src(), @as(c_long, 1));
    return 0;
}
