const Args = @import("args.zig");

/// Syscall name (e.g. read, write ...).
name: []const u8,

const Self = @This();

/// Return ELF section name for syscall entry used by libbpf.
pub fn entry_section(comptime self: Self) []const u8 {
    return "ksyscall/" ++ self.name;
}

/// Return ELF section name for syscall exit used by libbpf.
pub fn exit_section(comptime self: Self) []const u8 {
    return "kretsyscall/" ++ self.name;
}

/// Return the argument retriever according to the specified syscall prototype.
pub fn Ctx(comptime self: Self) type {
    return Args.SYSCALL(self.name);
}
