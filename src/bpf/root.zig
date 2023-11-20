pub const Tracepoint = @import("tracepoint.zig");
pub const Map = @import("map.zig");
pub const Iterator = @import("iter.zig");
pub const Fentry = @import("fentry.zig");
pub const Kprobe = @import("kprobe.zig");
pub const Ksyscall = @import("ksyscall.zig");
pub const Args = @import("args.zig");
pub const Xdp = @import("xdp.zig");

const std = @import("std");
const trace_printk = std.os.linux.BPF.kern.helpers.trace_printk;
const builtin = std.builtin;
const SourceLocation = builtin.SourceLocation;
const StackTrace = builtin.StackTrace;

pub inline fn exit(comptime src: SourceLocation, ret: anytype) noreturn {
    const fmt = "error occur at %s:%d return %d";
    const file = @as(*const [src.file.len:0]u8, @ptrCast(src.file)).*;
    const line = src.line;

    _ = trace_printk(fmt, fmt.len + 1, @intFromPtr(&file), line, @bitCast(ret));

    asm volatile ("exit"
        :
        : [err] "{r0}" (0), // TODO: exit err?
    );

    unreachable;
}

pub fn panic(msg: []const u8, error_return_trace: ?*StackTrace, ret_addr: ?usize) noreturn {
    _ = error_return_trace;
    _ = ret_addr;

    var buffer = std.BoundedArray(u8, 128).fromSlice(msg) catch exit(@src(), @as(c_long, -1));
    buffer.append(0) catch exit(@src(), @as(c_long, -1));

    const fmt = "Panic: %s";
    _ = trace_printk(fmt, fmt.len + 1, @intFromPtr(buffer.constSlice().ptr), 0, 0);

    asm volatile ("exit"
        :
        : [err] "{r0}" (0), // TODO: exit err?
    );

    unreachable;
}

export const _license linksection("license") = "GPL".*;
