const std = @import("std");
const Args = @import("args.zig");
const vmlinux = @import("vmlinux");

/// Kernel function name.
name: []const u8,

const Self = @This();

/// Return ELF section name for kprobe used by libbpf.
pub fn entry_section(comptime self: Self) []const u8 {
    return "kprobe/" ++ self.name;
}

/// Return ELF section name for kretprobe used by libbpf.
pub fn exit_section(comptime self: Self) []const u8 {
    return "kretprobe/" ++ self.name;
}

/// Return the argument retriever according to the specified kernel function prototype.
pub fn Ctx(comptime self: Self) type {
    const func_name = "_zig_" ++ self.name;
    if (!@hasDecl(vmlinux, func_name))
        @compileError(std.fmt.comptimePrint("can't get function prototype for kernel function {s}", .{self.name}));

    return Args.PT_REGS(func_name, false);
}
