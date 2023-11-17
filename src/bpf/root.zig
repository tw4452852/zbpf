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
const SourceLocation = std.builtin.SourceLocation;

pub inline fn exit(comptime src: SourceLocation, ret: anytype) noreturn {
    @setCold(true);

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

export const _license linksection("license") = "GPL".*;
