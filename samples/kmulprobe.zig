const std = @import("std");
const bpf = @import("bpf");
const REGS = bpf.Args.REGS;
const helpers = std.os.linux.BPF.kern.helpers;
const trace_printk = helpers.trace_printk;
const exit = bpf.exit;

// pair pid_tid with REGS
var buffer = bpf.Map.HashMap("buffer", u64, REGS, 0xffff, 0).init();
var events = bpf.Map.RingBuffer("events", 16, 0).init();

export fn test_kmulprobe(regs: *REGS) linksection("kprobe.multi") callconv(.C) c_long {
    const tpid = helpers.get_current_pid_tgid();
    buffer.update(.any, tpid, regs.*);

    return 0;
}

export fn test_kmulretprobe(regs: *REGS) linksection("kretprobe.multi") callconv(.C) c_long {
    const tpid = helpers.get_current_pid_tgid();
    if (buffer.lookup(tpid)) |v| {
        const resv = events.reserve(REGS);
        resv.data_ptr.* = v.*;
        resv.data_ptr.ret_ptr().* = regs.ret_ptr().*;
        resv.commit();
    } else {
        const fmt = "exit failed\n";
        _ = trace_printk(fmt, fmt.len + 1, 0, 0, 0);
        exit(@src(), @as(c_long, 1));
    }

    return 0;
}
