const std = @import("std");
const bpf = @import("bpf");
const BPF = std.os.linux.BPF;
const helpers = BPF.kern.helpers;
const REGS = bpf.Args.REGS;
const TRACE_RECORD = bpf.Args.TRACE_RECORD;
const trace_printk = helpers.trace_printk;

const kprobes = @import("build_options").kprobes;
const syscalls = @import("build_options").syscalls;

var buffer = bpf.Map.HashMap("buffer", u64, REGS, 0xffff, 0).init();
var events = bpf.Map.RingBuffer("events", 16, 0).init();

fn generate_kprobe(comptime name: []const u8, comptime id: u32) type {
    return struct {
        const tracked_func = bpf.Kprobe{ .name = name };

        fn kprobe_entry(regs: *REGS) linksection(tracked_func.entry_section()) callconv(.C) c_long {
            const tpid = helpers.get_current_pid_tgid();
            buffer.update(.any, tpid, regs.*);

            return 0;
        }

        comptime {
            @export(kprobe_entry, .{ .name = name ++ "_kprobe_entry" });
        }

        fn kprobe_exit(regs: *REGS) linksection(tracked_func.exit_section()) callconv(.C) c_long {
            const tpid = helpers.get_current_pid_tgid();
            if (buffer.lookup(tpid)) |v| {
                const resv = events.reserve(TRACE_RECORD);
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
            @export(kprobe_exit, .{ .name = name ++ "_kprobe_exit" });
        }
    };
}

fn generate_syscall(comptime name: []const u8, comptime id: u32) type {
    return struct {
        const tracked_syscall = bpf.Ksyscall{ .name = name };

        fn syscall_entry(args: *tracked_syscall.Ctx()) linksection(tracked_syscall.entry_section()) callconv(.C) c_long {
            const tpid = helpers.get_current_pid_tgid();

            buffer.update(.any, tpid, std.mem.zeroes(REGS));
            if (buffer.lookup(tpid)) |v| {
                const err = helpers.probe_read_kernel(v, @sizeOf(REGS), args.get_arg_ctx().get_regs());
                if (err != 0) return 1;
            } else return 1;

            return 0;
        }

        comptime {
            @export(syscall_entry, .{ .name = name ++ "_syscall_entry" });
        }

        fn syscall_exit(args: *tracked_syscall.Ctx()) linksection(tracked_syscall.exit_section()) callconv(.C) c_long {
            const tpid = helpers.get_current_pid_tgid();
            if (buffer.lookup(tpid)) |v| {
                const ret = args.ret();
                const resv = events.reserve(TRACE_RECORD);
                v.ret_ptr().* = @bitCast(ret);
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
            @export(syscall_exit, .{ .name = name ++ "_syscall_exit" });
        }
    };
}

comptime {
    inline for (kprobes, 0..) |f, i| {
        _ = generate_kprobe(f, i);
    }

    inline for (syscalls, kprobes.len..) |f, i| {
        _ = generate_syscall(f, i);
    }
}
