const std = @import("std");
const bpf = @import("bpf");
const BPF = std.os.linux.BPF;
const helpers = BPF.kern.helpers;
const REGS = bpf.Args.REGS;
const TRACE_RECORD = bpf.Args.TRACE_RECORD;
const vmlinux = @import("vmlinux");

var events = bpf.Map.RingBuffer("events", 16, 0).init();
var stackmap = bpf.Map.StackTraceMap("stackmap", 16384).init();

fn generate_kprobe(comptime name: []const u8, comptime id: u32, comptime with_stack: bool) type {
    return struct {
        const tracked_func = bpf.Kprobe{ .name = name };

        fn kprobe_entry(regs: *REGS) linksection(tracked_func.entry_section()) callconv(.C) c_long {
            const tpid = helpers.get_current_pid_tgid();
            const stack_id = if (with_stack) stackmap.get_current_stack(regs, vmlinux.BPF_F_REUSE_STACKID) else -1;
            const resv = events.reserve(extern struct {
                record: TRACE_RECORD,
                extra: [tracked_func.Ctx().extra_record_size()]u8 = undefined,
            });
            resv.data_ptr.* = .{
                .record = .{
                    .id = id,
                    .tpid = tpid,
                    .regs = tracked_func.Ctx().deep_copy_to_user(regs, @intFromPtr(&resv.data_ptr.extra), true),
                    .extra_offset = @intFromPtr(&resv.data_ptr.extra) - @intFromPtr(resv.data_ptr),
                    .entry = true,
                    .stack_id = stack_id,
                },
            };
            resv.commit();

            return 0;
        }

        comptime {
            @export(kprobe_entry, .{ .name = name ++ "_kprobe_entry" });
        }

        fn kprobe_exit(regs: *REGS) linksection(tracked_func.exit_section()) callconv(.C) c_long {
            const tpid = helpers.get_current_pid_tgid();
            const resv = events.reserve(extern struct {
                record: TRACE_RECORD,
                extra: [tracked_func.Ctx().extra_record_size()]u8 = undefined,
            });
            resv.data_ptr.* = .{
                .record = .{
                    .id = id,
                    .tpid = tpid,
                    .regs = tracked_func.Ctx().deep_copy_to_user(regs, @intFromPtr(&resv.data_ptr.extra), false),
                    .extra_offset = @intFromPtr(&resv.data_ptr.extra) - @intFromPtr(resv.data_ptr),
                    .entry = false,
                    .stack_id = -1,
                },
            };
            resv.commit();
            return 0;
        }

        comptime {
            @export(kprobe_exit, .{ .name = name ++ "_kprobe_exit" });
        }
    };
}

fn generate_syscall(comptime name: []const u8, comptime id: u32, with_stack: bool) type {
    return struct {
        const tracked_syscall = bpf.Ksyscall{ .name = name };

        fn syscall_entry(args: *tracked_syscall.Ctx()) linksection(tracked_syscall.entry_section()) callconv(.C) c_long {
            var regs: REGS = undefined;
            const err = helpers.probe_read_kernel(&regs, @sizeOf(REGS), args.get_arg_ctx().get_regs());
            if (err != 0) {
                bpf.exit(@src(), err);
            }

            const tpid = helpers.get_current_pid_tgid();
            const stack_id = if (with_stack) stackmap.get_current_stack(args, vmlinux.BPF_F_REUSE_STACKID) else -1;
            const resv = events.reserve(extern struct {
                record: TRACE_RECORD,
                extra: [tracked_syscall.Ctx().extra_record_size()]u8 = undefined,
            });
            resv.data_ptr.* = .{
                .record = .{
                    .id = id,
                    .tpid = tpid,
                    .regs = tracked_syscall.Ctx().deep_copy_to_user(&regs, @intFromPtr(&resv.data_ptr.extra), true),
                    .extra_offset = @intFromPtr(&resv.data_ptr.extra) - @intFromPtr(resv.data_ptr),
                    .entry = true,
                    .stack_id = stack_id,
                },
            };
            resv.commit();

            return 0;
        }

        comptime {
            @export(syscall_entry, .{ .name = name ++ "_syscall_entry" });
        }

        fn syscall_exit(args: *tracked_syscall.Ctx()) linksection(tracked_syscall.exit_section()) callconv(.C) c_long {
            var regs: REGS = undefined;
            regs.ret_ptr().* = @bitCast(args.ret());

            const tpid = helpers.get_current_pid_tgid();
            const resv = events.reserve(extern struct {
                record: TRACE_RECORD,
                extra: [tracked_syscall.Ctx().extra_record_size()]u8 = undefined,
            });

            resv.data_ptr.* = .{
                .record = .{
                    .id = id,
                    .tpid = tpid,
                    .regs = tracked_syscall.Ctx().deep_copy_to_user(&regs, @intFromPtr(&resv.data_ptr.extra), false),
                    .extra_offset = @intFromPtr(&resv.data_ptr.extra) - @intFromPtr(resv.data_ptr),
                    .entry = false,
                    .stack_id = -1,
                },
            };
            resv.commit();
            return 0;
        }

        comptime {
            @export(syscall_exit, .{ .name = name ++ "_syscall_exit" });
        }
    };
}

comptime {
    for (@import("build_options").tracing_funcs, 0..) |f, i| {
        if (f.kind == .kprobe) {
            _ = generate_kprobe(f.name, i, f.with_stack);
        } else {
            _ = generate_syscall(f.name, i, f.with_stack);
        }
    }
}
