const std = @import("std");
const bpf = @import("bpf");
const comm = @import("comm.zig");
const BPF = std.os.linux.BPF;
const helpers = BPF.kern.helpers;
const REGS = bpf.Args.REGS;
const TRACE_RECORD = comm.TRACE_RECORD;
const vmlinux = @import("vmlinux");

var events = bpf.Map.RingBuffer("events", 16, 0).init();
var stackmap = bpf.Map.StackTraceMap("stackmap", 16384).init();

fn generate(comptime name: []const u8, comptime id: u32, comptime with_stack: bool, comptime args_capture: []const []const u8, comptime is_syscall: bool) type {
    return struct {
        const F = if (is_syscall) bpf.Ksyscall{ .name = name } else bpf.Kprobe{ .name = name };
        const Arg = comm.Arg(name, is_syscall);
        const entry_extra_size = es: {
            var size = 0;
            for (args_capture) |arg| {
                if (std.mem.startsWith(u8, arg, "arg")) {
                    const FT = Arg.Field(arg);
                    size += @sizeOf(FT);
                }
            }
            break :es size;
        };
        const exit_extra_size = es: {
            var size = 0;
            for (args_capture) |arg| {
                if (std.mem.startsWith(u8, arg, "ret")) {
                    const FT = Arg.Field(arg);
                    size += @sizeOf(FT);
                }
            }
            break :es size;
        };

        fn _entry(ctx: *F.Ctx()) linksection(F.entry_section()) callconv(.C) c_long {
            const tpid = helpers.get_current_pid_tgid();
            const stack_id = if (with_stack) stackmap.get_current_stack(ctx, 1024) else -1;
            const resv = events.reserve(extern struct {
                record: TRACE_RECORD,
                extra: [entry_extra_size]u8 = undefined,
            });
            resv.data_ptr.* = .{
                .record = .{
                    .id = id,
                    .tpid = tpid,
                    .entry = true,
                    .stack_id = stack_id,
                },
            };
            var buf: [*c]u8 = @ptrCast(&resv.data_ptr.extra);
            inline for (args_capture) |arg| {
                if (comptime std.mem.startsWith(u8, arg, "arg")) Arg.copy(arg, ctx, &buf);
            }
            resv.commit();

            return 0;
        }

        comptime {
            @export(&_entry, .{ .name = name ++ if (is_syscall) "_syscall_entry" else "_kprobe_entry" });
        }

        fn _exit(ctx: *F.Ctx()) linksection(F.exit_section()) callconv(.C) c_long {
            const tpid = helpers.get_current_pid_tgid();
            const resv = events.reserve(extern struct {
                record: TRACE_RECORD,
                extra: [exit_extra_size]u8 = undefined,
            });

            resv.data_ptr.* = .{
                .record = .{
                    .id = id,
                    .tpid = tpid,
                    .entry = false,
                    .stack_id = -1,
                },
            };
            var buf: [*c]u8 = @ptrCast(&resv.data_ptr.extra);
            inline for (args_capture) |arg| {
                if (comptime std.mem.startsWith(u8, arg, "ret")) Arg.copy(arg, ctx, &buf);
            }
            resv.commit();
            return 0;
        }

        comptime {
            var want_ret = false;
            for (args_capture) |arg| {
                if (std.mem.startsWith(u8, arg, "ret")) {
                    want_ret = true;
                    break;
                }
            }
            if (want_ret) {
                @export(&_exit, .{ .name = name ++ if (is_syscall) "_syscall_exit" else "_kprobe_exit" });
            }
        }
    };
}

comptime {
    for (@import("@build_options").tracing_funcs, 0..) |f, i| {
        _ = generate(f.name, i, f.with_stack, f.args, f.kind == .syscall);
    }
}
