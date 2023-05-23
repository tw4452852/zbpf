const Args = @import("args.zig");

name: []const u8,

const Self = @This();

pub fn entry_section(comptime self: Self) []const u8 {
    return "ksyscall/" ++ self.name;
}

pub fn exit_section(comptime self: Self) []const u8 {
    return "kretsyscall/" ++ self.name;
}

pub fn Ctx(comptime self: Self) type {
    return Args.SYSCALL(self.name);
}
