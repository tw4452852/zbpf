const std = @import("std");
const bpf = @import("bpf");
const BPF = std.os.linux.BPF;
const helpers = BPF.kern.helpers;

var events = bpf.Map.PerfEventArray("events", 0, 0).init();
var my_pid = bpf.Map.ArrayMap("my_pid", u32, 1, 0).init();

export fn test_perf_event_array(ctx: *opaque {}) linksection("kprobe/do_nanosleep") c_int {
    const pid = my_pid.lookup(0) orelse return 1;

    const cur_pid: u32 = @truncate(helpers.get_current_pid_tgid());
    if (cur_pid == pid.*) {
        events.event_output(ctx, null, "hello") catch return 1;
    }
    return 0;
}
