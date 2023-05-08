const std = @import("std");
const bpf = @import("bpf");
const BPF = std.os.linux.BPF;
const helpers = BPF.kern.helpers;

var events = bpf.Map.RingBuffer("events", 1, 0).init();
var my_pid = bpf.Map.ArrayMap("my_pid", u32, 1, 0).init();

var n: u32 = 0;

export fn test_ringbuf() linksection("kprobe/do_nanosleep") c_int {
    const pid = my_pid.lookup(0) orelse return 1;

    const cur_pid = @truncate(u32, helpers.get_current_pid_tgid());
    if (cur_pid == pid.*) {
        var a: u8 = '1';
        if (n % 2 == 1) {
            events.event_output(std.mem.asBytes(&a), @intToEnum(bpf.Map.RingBufNotify, n % 3)) catch return 1;
        } else {
            const resv = events.reserve(@TypeOf(a)) catch return 2;
            resv.data_ptr.* = a;
            resv.commit();
        }

        n += 1;
    }
    return 0;
}
