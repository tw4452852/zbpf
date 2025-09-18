const std = @import("std");
const trace_printk = std.os.linux.BPF.kern.helpers.trace_printk;
const builtin = std.builtin;
const SourceLocation = builtin.SourceLocation;
const StackTrace = builtin.StackTrace;

/// Argument retriever according to different context.
pub const Args = @import("args.zig");
/// Represent [fentry/fexit](https://docs.kernel.org/trace/fprobe.html) in bpf program.
pub const Fentry = @import("fentry.zig");
/// Represent [BPF Iterator](https://docs.kernel.org/bpf/bpf_iterators.html) in bpf program.
pub const Iterator = @import("iter.zig");
/// Represent [kprobe/kretprobe](https://docs.kernel.org/trace/kprobes.html?highlight=kprobe) in bpf program.
pub const Kprobe = @import("kprobe.zig");
/// Represent syscall in bpf program.
pub const Ksyscall = @import("ksyscall.zig");
/// Represent all kinds of maps in BPF.
pub const Map = @import("map.zig");
/// Represent TC in bpf program.
pub const Tc = @import("tc.zig");
/// Represent [tracepoints](https://docs.kernel.org/trace/tracepoints.html) in kernel.
pub const Tracepoint = @import("tracepoint.zig");
/// Represent Uprobe in bpf program.
pub const Uprobe = @import("uprobe.zig");
/// Represent XDP in bpf program.
pub const Xdp = @import("xdp.zig");

pub inline fn printErr(comptime src: SourceLocation, ret: c_long) void {
    const fmt = "error occur at %s:%d return %d";
    const file = @as(*const [src.file.len:0]u8, @ptrCast(src.file)).*;
    const line = src.line;

    _ = trace_printk(fmt, fmt.len + 1, @intFromPtr(&file), line, @bitCast(ret));
}

/// Default implementation of panic handler for bpf
/// you could register with Zig by writing the following in your bpf program:
/// ```
/// pub const panic = bpf.panic;
/// ```
/// Currently, it will only print the panic message in kernel's trace buffer
/// and exit current bpf program.
pub inline fn panic(msg: []const u8, error_return_trace: ?*StackTrace, ret_addr: ?usize) noreturn {
    _ = error_return_trace;
    _ = ret_addr;

    var buffer: [128]u8 = undefined;
    var list = std.ArrayListUnmanaged(u8).initBuffer(&buffer);
    list.appendSliceBounded(msg) catch {};
    list.appendBounded(0) catch {};

    const fmt = "Panic: %s";
    _ = trace_printk(fmt, fmt.len + 1, @intFromPtr(&buffer), 0, 0);

    unreachable;
}

export const _license linksection("license") = "GPL".*;

export fn __bpf_trap() c_long {
    return 0xdead;
}
