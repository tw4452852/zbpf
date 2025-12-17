const vmlinux = @import("vmlinux");
const kfuncs = vmlinux.kernel_funcs;
const ksyscalls = vmlinux.kernel_syscalls;
const std = @import("std");
const StructField = std.builtin.Type.StructField;
const helpers = std.os.linux.BPF.kern.helpers;
const printErr = @import("root.zig").printErr;

extern var LINUX_HAS_SYSCALL_WRAPPER: bool linksection(".kconfig");

const arch: std.Target.Cpu.Arch = if (@hasDecl(kfuncs, "__x64_sys_write"))
    .x86_64
else if (@hasDecl(kfuncs, "__ia32_sys_write"))
    .x86
else if (@hasDecl(kfuncs, "__arm64_sys_write"))
    .aarch64
else if (@hasDecl(kfuncs, "__arm_sys_write"))
    .arm
else
    @compileError(std.fmt.comptimePrint("unknown arch", .{}));

const in_bpf_program = switch (@import("builtin").cpu.arch) {
    .bpfel, .bpfeb => true,
    else => false,
};

/// Return argument context according to the specified kernel function prototype.
pub fn Ctx(comptime func_name: []const u8) type {
    const f = @typeInfo(@typeInfo(@field(kfuncs, func_name)).pointer.child);
    const fn_params = f.@"fn".params;
    var field_names: [fn_params.len + 1][]const u8 = undefined;
    var field_types: [fn_params.len + 1]type = undefined;
    var field_attrs: [fn_params.len + 1]std.builtin.Type.StructField.Attributes = undefined;

    for (0..fn_params.len) |i| {
        field_names[i] = std.fmt.comptimePrint("arg{}", .{i});
        field_types[i] = fn_params[i].type.?;
        field_attrs[i] = .{
            .@"comptime" = false,
            .@"align" = @sizeOf(u64),
            .default_value_ptr = null,
        };
    }

    field_names[fn_params.len] = "ret";
    field_types[fn_params.len] = f.@"fn".return_type.?;
    field_attrs[fn_params.len] = .{
        .@"comptime" = false,
        .@"align" = @sizeOf(u64),
        .default_value_ptr = null,
    };

    return @Struct(.@"extern", null, &field_names, &field_types, &field_attrs);
}

/// Represent `struct pt_regs` for different architectures.
pub const REGS = struct {
    const Self = @This();
    impl: switch (arch) {
        .x86, .x86_64, .arm => vmlinux.pt_regs,
        .aarch64 => vmlinux.user_pt_regs,
        else => @panic("toto"),
    },

    /// return pointer to the arg0 in the pt_regs.
    pub fn arg0_ptr(self: *Self) *c_ulong {
        return switch (arch) {
            .x86_64 => &self.impl.di,
            .x86 => &self.impl.eax,
            .arm => &self.impl.uregs[0],
            .aarch64 => &self.impl.regs[0],
            else => {},
        };
    }

    /// return pointer to the arg1 in the pt_regs.
    pub fn arg1_ptr(self: *Self) *c_ulong {
        return switch (arch) {
            .x86_64 => &self.impl.si,
            .x86 => &self.impl.edx,
            .arm => &self.impl.uregs[1],
            .aarch64 => &self.impl.regs[1],
            else => {},
        };
    }

    /// return pointer to the arg2 in the pt_regs.
    pub fn arg2_ptr(self: *Self) *c_ulong {
        return switch (arch) {
            .x86_64 => &self.impl.dx,
            .x86 => &self.impl.ecx,
            .arm => &self.impl.uregs[2],
            .aarch64 => &self.impl.regs[2],
            else => {},
        };
    }

    /// return pointer to the arg3 in the pt_regs.
    pub fn arg3_ptr(self: *Self, for_syscall: bool) *c_ulong {
        return switch (arch) {
            .x86_64 => if (for_syscall) &self.impl.r10 else &self.impl.cx,
            .x86 => @compileError(std.fmt.comptimePrint("not support arg3 on i386", .{})),
            .arm => &self.impl.uregs[3],
            .aarch64 => &self.impl.regs[3],
            else => {},
        };
    }

    /// return pointer to the arg4 in the pt_regs.
    pub fn arg4_ptr(self: *Self) *c_ulong {
        return switch (arch) {
            .x86_64 => &self.impl.r8,
            .x86 => @compileError(std.fmt.comptimePrint("not support arg4 on i386", .{})),
            .arm => &self.impl.uregs[4],
            .aarch64 => &self.impl.regs[4],
            else => {},
        };
    }

    /// return pointer to the return value in the pt_regs.
    pub fn ret_ptr(self: *Self) *c_ulong {
        return switch (arch) {
            .x86_64 => &self.impl.ax,
            .x86 => &self.impl.eax,
            .arm => &self.impl.uregs[0],
            .aarch64 => &self.impl.regs[0],
            else => {},
        };
    }
};

/// Check if the type is ?*T or *T.
pub inline fn is_pointer(comptime typ: type) bool {
    const ti = @typeInfo(typ);
    return ti == .pointer or (ti == .optional and @typeInfo(ti.optional.child) == .pointer);
}

/// Get the pointee type
pub inline fn deref_pointer(comptime typ: type) type {
    const ti = @typeInfo(typ);
    return switch (ti) {
        inline .pointer => |info| return info.child,
        inline .optional => |info| return @typeInfo(info.child).pointer.child,
        else => @compileLog(ti),
    };
}

/// Cast `c_ulong` value into the corresponding type.
pub fn cast(comptime T: type, rc: c_ulong) T {
    if (is_pointer(T)) return @ptrFromInt(rc);

    const ti = @typeInfo(T);
    if (ti == .int) {
        if (ti.int.signedness == .signed) {
            return @truncate(@as(c_long, @bitCast(rc)));
        }
        return @truncate(rc);
    }
    if (ti == .@"enum") return @enumFromInt(rc);

    if (T == bool) return rc == 1;

    return rc;
}

/// Return the actual type to retrive arguments for the specified kernel function.
/// As syscall function has different retrieving method than regular kernel function,
/// this will hide the underlying mechanism to provider a consistent API.
pub fn PT_REGS(comptime func_name: []const u8, comptime for_syscall: bool) type {
    const f = if (for_syscall)
        @typeInfo(@field(ksyscalls, func_name))
    else
        @typeInfo(@typeInfo(@field(kfuncs, func_name)).pointer.child);

    return opaque {
        const Self = @This();

        /// helper function to return the underlying `REG`.
        pub inline fn get_regs(self: *Self) *REGS {
            return @ptrCast(@alignCast(self));
        }

        const ARG0 = if (f.@"fn".params.len < 1) @compileError("not support") else f.@"fn".params[0].type.?;
        pub fn arg0(self: *Self) ARG0 {
            if (!in_bpf_program) {
                return cast(ARG0, self.get_regs().arg0_ptr().*);
            } else {
                var result: ARG0 = undefined;
                const err = helpers.probe_read_kernel(@ptrCast(&result), @sizeOf(ARG0), self.get_regs().arg0_ptr());
                if (err != 0) printErr(@src(), err);
                return result;
            }
        }

        const ARG1 = if (f.@"fn".params.len < 2) @compileError("not support") else f.@"fn".params[1].type.?;
        pub fn arg1(self: *Self) ARG1 {
            if (!in_bpf_program) {
                return cast(ARG1, self.get_regs().arg1_ptr().*);
            } else {
                var result: ARG1 = undefined;
                const err = helpers.probe_read_kernel(@ptrCast(&result), @sizeOf(ARG1), self.get_regs().arg1_ptr());
                if (err != 0) printErr(@src(), err);
                return result;
            }
        }

        const ARG2 = if (f.@"fn".params.len < 3) @compileError("not support") else f.@"fn".params[2].type.?;
        pub fn arg2(self: *Self) ARG2 {
            if (!in_bpf_program) {
                return cast(ARG2, self.get_regs().arg2_ptr().*);
            } else {
                var result: ARG2 = undefined;
                const err = helpers.probe_read_kernel(@ptrCast(&result), @sizeOf(ARG2), self.get_regs().arg2_ptr());
                if (err != 0) printErr(@src(), err);
                return result;
            }
        }

        const ARG3 = if (f.@"fn".params.len < 4) @compileError("not support") else f.@"fn".params[3].type.?;
        pub fn arg3(self: *Self) ARG3 {
            if (!in_bpf_program) {
                return cast(ARG3, self.get_regs().arg3_ptr(for_syscall).*);
            } else {
                var result: ARG3 = undefined;
                const err = helpers.probe_read_kernel(@ptrCast(&result), @sizeOf(ARG3), self.get_regs().arg3_ptr(for_syscall));
                if (err != 0) printErr(@src(), err);
                return result;
            }
        }

        const ARG4 = if (f.@"fn".params.len < 5) @compileError("not support") else f.@"fn".params[4].type.?;
        pub fn arg4(self: *Self) ARG4 {
            if (!in_bpf_program) {
                return cast(ARG4, self.get_regs().arg4_ptr().*);
            } else {
                var result: ARG4 = undefined;
                const err = helpers.probe_read_kernel(@ptrCast(&result), @sizeOf(ARG4), self.get_regs().arg4_ptr());
                if (err != 0) printErr(@src(), err);
                return result;
            }
        }

        const RET = if (f.@"fn".return_type.? == void) @compileError("not support") else f.@"fn".return_type.?;
        pub fn ret(self: *Self) RET {
            if (!in_bpf_program) {
                return cast(RET, self.get_regs().ret_ptr().*);
            } else {
                var v: RET = undefined;
                const err = helpers.probe_read_kernel(@ptrCast(&v), @sizeOf(RET), self.get_regs().ret_ptr());
                if (err != 0) printErr(@src(), err);
                return v;
            }
        }
    };
}

/// A Wrapper type for syscall arguments retrieving.
pub fn SYSCALL(comptime name: []const u8) type {
    const f = @typeInfo(@field(ksyscalls, name));
    const T = PT_REGS(name, true);

    return opaque {
        const Self = @This();

        /// helper function to get underlying `PT_REGS`.
        pub inline fn get_arg_ctx(self: *Self) *T {
            if (!in_bpf_program) return @ptrCast(self);

            return if (LINUX_HAS_SYSCALL_WRAPPER)
                @ptrFromInt(@as(*REGS, @ptrCast(@alignCast(self))).arg0_ptr().*)
            else
                @ptrCast(self);
        }

        const ARG0 = if (f.@"fn".params.len < 1) @compileError("not support") else f.@"fn".params[0].type.?;
        pub fn arg0(self: *Self) ARG0 {
            return self.get_arg_ctx().arg0();
        }

        const ARG1 = if (f.@"fn".params.len < 2) @compileError("not support") else f.@"fn".params[1].type.?;
        pub fn arg1(self: *Self) ARG1 {
            return self.get_arg_ctx().arg1();
        }

        const ARG2 = if (f.@"fn".params.len < 3) @compileError("not support") else f.@"fn".params[2].type.?;
        pub fn arg2(self: *Self) ARG2 {
            return self.get_arg_ctx().arg2();
        }

        const ARG3 = if (f.@"fn".params.len < 4) @compileError("not support") else f.@"fn".params[3].type.?;
        pub fn arg3(self: *Self) ARG3 {
            return self.get_arg_ctx().arg3();
        }

        const ARG4 = if (f.@"fn".params.len < 5) @compileError("not support") else f.@"fn".params[4].type.?;
        pub fn arg4(self: *Self) RET {
            return self.get_arg_ctx().arg4();
        }

        const RET = if (f.@"fn".return_type.? == void) @compileError("not support") else f.@"fn".return_type.?;
        pub fn ret(self: *Self) RET {
            return @as(*T, @ptrCast(self)).ret();
        }
    };
}
