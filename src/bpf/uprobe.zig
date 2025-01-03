const std = @import("std");
const Args = @import("args.zig");

/// Userspace binary name.
name: []const u8,
/// Function name.
func: []const u8,
/// Optional offset in the function
offset: ?u64 = null,

const Self = @This();

/// Return ELF section name for uprobe used by libbpf.
pub fn entry_section(comptime self: Self) []const u8 {
    return "uprobe/" ++ self.name ++ ":" ++ self.func ++ if (self.offset) |offset| std.fmt.comptimePrint("+{}", .{offset}) else "";
}

/// Return ELF section name for uretprobe used by libbpf.
pub fn exit_section(comptime self: Self) []const u8 {
    return "uretprobe/" ++ self.name ++ ":" ++ self.func;
}

/// Return the argument retriever.
pub fn Ctx(comptime _: Self) type {
    return opaque {
        const Impl = @This();

        pub fn arg0(self: *Impl) c_ulong {
            return Args.REGS.arg0_ptr(@alignCast(@ptrCast(self))).*;
        }
        pub fn arg1(self: *Impl) c_ulong {
            return Args.REGS.arg1_ptr(@alignCast(@ptrCast(self))).*;
        }
        pub fn arg2(self: *Impl) c_ulong {
            return Args.REGS.arg2_ptr(@alignCast(@ptrCast(self))).*;
        }
        pub fn arg3(self: *Impl) c_ulong {
            return Args.REGS.arg3_ptr(@alignCast(@ptrCast(self))).*;
        }
        pub fn arg4(self: *Impl) c_ulong {
            return Args.REGS.arg4_ptr(@alignCast(@ptrCast(self))).*;
        }
        pub fn ret(self: *Impl) c_ulong {
            return Args.REGS.ret_ptr(@alignCast(@ptrCast(self))).*;
        }
    };
}
