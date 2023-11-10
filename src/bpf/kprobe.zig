const Args = @import("args.zig");

name: []const u8,

const Self = @This();

pub fn entry_section(comptime self: Self) []const u8 {
    return "kprobe/" ++ self.name;
}

pub fn exit_section(comptime self: Self) []const u8 {
    return "kretprobe/" ++ self.name;
}

pub fn Ctx(comptime self: Self) type {
    return Args.PT_REGS("_zig_" ++ self.name, false);
}
