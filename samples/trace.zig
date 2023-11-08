const traced_funcs = @import("build_options").traced_funcs;
const std = @import("std");
const bpf = @import("bpf");
const BPF = std.os.linux.BPF;
const helpers = BPF.kern.helpers;
const REGS = bpf.Args.REGS;
const TRACE_RECORD = bpf.Args.TRACE_RECORD;
const trace_printk = helpers.trace_printk;

var buffer = bpf.Map.HashMap("buffer", u64, REGS, 0xffff, 0).init();
var events = bpf.Map.RingBuffer("events", 16, 0).init();

fn generate(comptime name: []const u8, comptime id: u32) type {
    return struct {
        const tracked_func = bpf.Kprobe{ .name = name };

        fn kprobe_entry(regs: *REGS) linksection(tracked_func.entry_section()) callconv(.C) c_long {
            const tpid = helpers.get_current_pid_tgid();
            buffer.update(.any, tpid, regs.*) catch return 1;

            return 0;
        }

        comptime {
            @export(kprobe_entry, .{ .name = name ++ "_entry" });
        }

        fn kprobe_exit(regs: *REGS) linksection(tracked_func.exit_section()) callconv(.C) c_long {
            const tpid = helpers.get_current_pid_tgid();
            if (buffer.lookup(tpid)) |v| {
                const resv = events.reserve(TRACE_RECORD) catch return 2;
                v.ret_ptr().* = regs.ret_ptr().*;
                resv.data_ptr.* = .{
                    .id = id,
                    .tpid = tpid,
                    .regs = v.*,
                };
                resv.commit();
            } else {
                const fmt = "exit failed\n";
                _ = trace_printk(fmt, fmt.len + 1, 0, 0, 0);
                return 1;
            }

            return 0;
        }

        comptime {
            @export(kprobe_exit, .{ .name = name ++ "_exit" });
        }
    };
}

comptime {
    inline for (traced_funcs, 0..) |f, i| {
        _ = generate(f, i);
    }
}
