pub const Tracepoint = @import("tracepoint.zig");
pub const Map = @import("map.zig");
pub const Iterator = @import("iter.zig");
pub const Fentry = @import("fentry.zig");
pub const Kprobe = @import("kprobe.zig");
pub const Ksyscall = @import("ksyscall.zig");
pub const Args = @import("args.zig");
pub const Xdp = @import("xdp.zig");

pub inline fn exit(_: anyerror) noreturn {
    @setCold(true);

    asm volatile ("exit"
        :
        : [err] "{r0}" (0), // TODO: exit err?
    );
    unreachable;
}

export const _license linksection("license") = "GPL".*;
