pub const Tracepoint = @import("tracepoint.zig");
pub const Map = @import("map.zig");
pub const Iterator = @import("iter.zig");
pub const Fentry = @import("fentry.zig");
pub const Kprobe = @import("kprobe.zig");
pub const Ksyscall = @import("ksyscall.zig");
pub const Args = @import("args.zig");

export const _license linksection("license") = "GPL".*;
