const Args = @import("args.zig");

name: []const u8,

const Self = @This();

pub fn entry_section(comptime self: Self) []const u8 {
    return "fentry/" ++ self.name;
}

pub fn exit_section(comptime self: Self) []const u8 {
    return "fexit/" ++ self.name;
}

pub fn Ctx(comptime self: Self) type {
    return Args.Ctx(self.name);
}
