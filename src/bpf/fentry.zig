const Args = @import("args.zig");

/// Kernel function name.
name: []const u8,

const Self = @This();

/// Return ELF section name for fentry used by libbpf.
pub fn entry_section(comptime self: Self) []const u8 {
    return "fentry/" ++ self.name;
}

/// Return ELF section name for fexit used by libbpf.
pub fn exit_section(comptime self: Self) []const u8 {
    return "fexit/" ++ self.name;
}

/// Return the argument retriever according to the specified kernel function prototype.
pub fn Ctx(comptime self: Self) type {
    return Args.Ctx(self.name);
}
