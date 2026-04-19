const std = @import("std");
const bpf = @import("bpf");
const BPF = std.os.linux.BPF;
const helpers = BPF.kern.helpers;

var events = bpf.Map.PerfEventArray("events", 0, 0).init();

const tracked_func = bpf.Kprobe{ .name = "do_faccessat" };

export fn test_perf_event_array(args: *tracked_func.Ctx()) linksection(tracked_func.entry_section()) callconv(.c) c_long {
    const arg2 = args.arg2();
    if (arg2 == 123456) {
        events.event_output(args, null, "hello");
    }
    return 0;
}
