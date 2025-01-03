const std = @import("std");
const bpf = @import("bpf");
const comm = @import("comm.zig");
const BPF = std.os.linux.BPF;
const helpers = BPF.kern.helpers;
const REGS = bpf.Args.REGS;
const TRACE_RECORD = comm.TRACE_RECORD;
const vmlinux = @import("vmlinux");
const build_options = @import("@build_options");

var events = bpf.Map.RingBuffer("events", 16, 0).init();
var stackmap = bpf.Map.StackTraceMap("stackmap", 16384).init();

fn generate(comptime id: u32, comptime tf: build_options.TraceFunc) type {
    return struct {
        const F = switch (tf.kind) {
            .syscall => bpf.Ksyscall{ .name = tf.name },
            .kprobe => bpf.Kprobe{ .name = tf.name },
            .uprobe => blk: {
                var it = std.mem.tokenizeAny(u8, tf.name, "[]");
                const path = it.next().?;
                const s = it.next().?;
                if (std.mem.indexOfScalar(u8, s, '+')) |i| {
                    const offset = std.fmt.parseInt(u64, s[i + 1 ..], 0) catch @panic("invalid offset");
                    break :blk bpf.Uprobe{ .name = path, .func = s[0..i], .offset = offset };
                } else break :blk bpf.Uprobe{ .name = path, .func = s };
            },
        };
        const identifier = switch (tf.kind) {
            .syscall, .kprobe => tf.name,
            .uprobe => F.func,
        };

        const Arg = comm.Arg(tf.name, tf.kind);
        const entry_extra_size = es: {
            var size = 0;
            for (tf.args) |arg| {
                if (std.mem.startsWith(u8, arg, "arg")) {
                    const FT = Arg.Field(arg);
                    size += @sizeOf(FT);
                }
            }
            break :es size;
        };
        const exit_extra_size = es: {
            var size = 0;
            for (tf.args) |arg| {
                if (std.mem.startsWith(u8, arg, "ret")) {
                    const FT = Arg.Field(arg);
                    size += @sizeOf(FT);
                }
            }
            break :es size;
        };

        fn _entry(ctx: *F.Ctx()) linksection(F.entry_section()) callconv(.C) c_long {
            const tpid = helpers.get_current_pid_tgid();
            const BPF_F_REUSE_STACKID = 1 << 10;
            const BPF_F_USER_STACK = 1 << 8;
            const flags = BPF_F_REUSE_STACKID | if (tf.kind == .uprobe) BPF_F_USER_STACK else 0;
            const stack_id = if (tf.with_stack) stackmap.get_current_stack(ctx, flags) else -1;

            const resv = events.reserve(TRACE_RECORD, entry_extra_size + @sizeOf([64]vmlinux.perf_branch_entry));
            resv.header_ptr.* = .{
                .id = id,
                .tpid = tpid,
                .entry = true,
                .stack_id = stack_id,
                .arg_size = entry_extra_size,
                .lbr_size = 0,
            };
            if (tf.with_lbr) {
                resv.header_ptr.lbr_size = helpers.get_branch_snapshot(resv.trail_ptr + entry_extra_size, @sizeOf([64]vmlinux.perf_branch_entry), 0);
            }

            var buf: [*c]u8 = resv.trail_ptr;
            inline for (tf.args) |arg| {
                if (comptime std.mem.startsWith(u8, arg, "arg")) Arg.copy(arg, ctx, &buf);
            }

            resv.commit();

            return 0;
        }

        comptime {
            @export(&_entry, .{ .name = identifier ++ switch (tf.kind) {
                .syscall => "_syscall_entry",
                .kprobe => "_kprobe_entry",
                .uprobe => "_uprobe_entry",
            } });
        }

        fn _exit(ctx: *F.Ctx()) linksection(F.exit_section()) callconv(.C) c_long {
            const tpid = helpers.get_current_pid_tgid();
            const resv = events.reserve(TRACE_RECORD, exit_extra_size);

            resv.header_ptr.* = .{
                .id = id,
                .tpid = tpid,
                .entry = false,
                .stack_id = -1,
                .arg_size = exit_extra_size,
                .lbr_size = 0,
            };
            var buf: [*c]u8 = resv.trail_ptr;
            inline for (tf.args) |arg| {
                if (comptime std.mem.startsWith(u8, arg, "ret")) Arg.copy(arg, ctx, &buf);
            }
            resv.commit();
            return 0;
        }

        comptime {
            var want_ret = false;
            for (tf.args) |arg| {
                if (std.mem.startsWith(u8, arg, "ret")) {
                    want_ret = true;
                    break;
                }
            }
            if (want_ret) {
                @export(&_exit, .{ .name = identifier ++ switch (tf.kind) {
                    .syscall => "_syscall_exit",
                    .kprobe => "_kprobe_exit",
                    .uprobe => "_uprobe_exit",
                } });
            }
        }
    };
}

comptime {
    for (build_options.tracing_funcs, 0..) |f, i| {
        _ = generate(i, f);
    }
}
