const vmlinux = @import("vmlinux");
const std = @import("std");
const StructField = std.builtin.Type.StructField;
const helpers = std.os.linux.BPF.kern.helpers;

extern var LINUX_HAS_SYSCALL_WRAPPER: bool linksection(".kconfig");

const func_prefix = "_zig_";

const arch: std.Target.Cpu.Arch = if (@hasDecl(vmlinux, func_prefix ++ "__x64_sys_write"))
    .x86_64
else if (@hasDecl(vmlinux, func_prefix ++ "__ia32_sys_write"))
    .x86
else if (@hasDecl(vmlinux, func_prefix ++ "__arm64_sys_write"))
    .aarch64
else if (@hasDecl(vmlinux, func_prefix ++ "__arm_sys_write"))
    .arm
else
    @compileError(std.fmt.comptimePrint("unknown arch", .{}));

pub fn Ctx(comptime func_name: []const u8) type {
    const f = @typeInfo(@TypeOf(@field(vmlinux, "_zig_" ++ func_name)));
    comptime var fields: []const StructField = &.{};

    for (0.., f.Fn.params) |i, arg| {
        fields = fields ++ [_]StructField{
            .{
                .name = std.fmt.comptimePrint("arg{}", .{i}),
                .type = arg.type.?,
                .default_value = null,
                .is_comptime = false,
                .alignment = @sizeOf(u64),
            },
        };
    }

    fields = fields ++ [_]StructField{
        .{
            .name = "ret",
            .type = f.Fn.return_type.?,
            .default_value = null,
            .is_comptime = false,
            .alignment = @sizeOf(u64),
        },
    };

    return @Type(.{
        .Struct = .{
            .layout = .Extern,
            .is_tuple = false,
            .fields = fields,
            .decls = &.{},
        },
    });
}

const REGS = opaque {
    const Self = @This();
    const S = switch (arch) {
        .x86, .x86_64, .arm => vmlinux.pt_regs,
        .aarch64 => vmlinux.user_pt_regs,
        else => {},
    };

    pub fn arg0_ptr(self: *Self) *c_ulong {
        const s = @ptrCast(*S, @alignCast(@alignOf(S), self));
        return switch (arch) {
            .x86_64 => &s.di,
            .x86 => &s.eax,
            .arm => &s.uregs[0],
            .aarch64 => &s.regs[0],
            else => {},
        };
    }

    pub fn arg1_ptr(self: *Self) *c_ulong {
        const s = @ptrCast(*S, @alignCast(@alignOf(S), self));
        return switch (arch) {
            .x86_64 => &s.si,
            .x86 => &s.edx,
            .arm => &s.uregs[1],
            .aarch64 => &s.regs[1],
            else => {},
        };
    }

    pub fn arg2_ptr(self: *Self) *c_ulong {
        const s = @ptrCast(*S, @alignCast(@alignOf(S), self));
        return switch (arch) {
            .x86_64 => &s.dx,
            .x86 => &s.ecx,
            .arm => &s.uregs[2],
            .aarch64 => &s.regs[2],
            else => {},
        };
    }

    pub fn arg3_ptr(self: *Self, for_syscall: bool) *c_ulong {
        const s = @ptrCast(*S, @alignCast(@alignOf(S), self));
        return switch (arch) {
            .x86_64 => if (for_syscall) &s.r10 else &s.cx,
            .x86 => @compileError(std.fmt.comptimePrint("not support arg3 on i386", .{})),
            .arm => &s.uregs[3],
            .aarch64 => &s.regs[3],
            else => {},
        };
    }

    pub fn arg4_ptr(self: *Self) *c_ulong {
        const s = @ptrCast(*S, @alignCast(@alignOf(S), self));
        return switch (arch) {
            .x86_64 => &s.r8,
            .x86 => @compileError(std.fmt.comptimePrint("not support arg4 on i386", .{})),
            .arm => &s.uregs[4],
            .aarch64 => &s.regs[4],
            else => {},
        };
    }

    pub fn ret_ptr(self: *Self) *c_ulong {
        const s = @ptrCast(*S, @alignCast(@alignOf(S), self));
        return switch (arch) {
            .x86_64 => &s.ax,
            .x86 => &s.eax,
            .arm => &s.uregs[0],
            .aarch64 => &s.regs[0],
            else => {},
        };
    }
};

pub fn PT_REGS(comptime func_name: []const u8) type {
    const f = @typeInfo(@TypeOf(@field(vmlinux, func_prefix ++ func_name)));

    return opaque {
        const Self = @This();

        pub usingnamespace if (f.Fn.params.len < 1) struct {} else struct {
            pub fn arg0(self: *Self) f.Fn.params[0].type.? {
                return @ptrCast(*REGS, self).arg0_ptr().*;
            }
        };

        pub usingnamespace if (f.Fn.params.len < 2) struct {} else struct {
            pub fn arg1(self: *Self) f.Fn.params[1].type.? {
                return @ptrCast(*REGS, self).arg1_ptr().*;
            }
        };

        pub usingnamespace if (f.Fn.params.len < 3) struct {} else struct {
            pub fn arg2(self: *Self) f.Fn.params[2].type.? {
                return @ptrCast(*REGS, self).arg2_ptr().*;
            }
        };

        pub usingnamespace if (f.Fn.params.len < 4) struct {} else struct {
            pub fn arg3(self: *Self) f.Fn.params[3].type.? {
                return @ptrCast(*REGS, self).arg3_ptr(false).*;
            }
        };

        pub usingnamespace if (f.Fn.params.len < 5) struct {} else struct {
            pub fn arg4(self: *Self) f.Fn.params[4].type.? {
                return @ptrCast(*REGS, self).arg4_ptr().*;
            }
        };

        const RET = f.Fn.return_type.?;
        const ti = @typeInfo(RET);
        const is_pointer = ti == .Pointer or (ti == .Optional and @typeInfo(ti.Optional.child) == .Pointer);
        pub usingnamespace if (RET == void) struct {} else struct {
            pub fn ret(self: *Self) RET {
                const rc = @ptrCast(*REGS, self).ret_ptr().*;
                return if (!is_pointer) @intCast(RET, rc) else rc;
            }
        };
    };
}

pub fn SYSCALL(comptime name: []const u8) type {
    const sys_prefix = switch (arch) {
        .x86_64 => "__x64_sys_",
        .x86 => "__ia32_sys_",
        .aarch64 => "__arm64_sys_",
        .arm => "__arm_sys_",
        else => {},
    };

    if (!@hasDecl(vmlinux, func_prefix ++ sys_prefix ++ name))
        @compileError(std.fmt.comptimePrint("can't determine the actual function name for syscall {s} on {}", .{ name, arch }));

    return opaque {
        const Self = @This();

        pub fn arg0(self: *Self) !c_ulong {
            if (LINUX_HAS_SYSCALL_WRAPPER) {
                const ctx = @intToPtr(*REGS, @ptrCast(*REGS, self).arg0_ptr().*);
                var d: c_ulong = undefined;
                const r = helpers.probe_read_kernel(&d, @sizeOf(c_ulong), ctx.arg0_ptr());
                return if (r != 0) error.READ_KERN else d;
            } else return @ptrCast(*REGS, self).arg0_ptr().*;
        }

        pub fn arg1(self: *Self) !c_ulong {
            if (LINUX_HAS_SYSCALL_WRAPPER) {
                const ctx = @intToPtr(*REGS, @ptrCast(*REGS, self).arg0_ptr().*);
                var d: c_ulong = undefined;
                const r = helpers.probe_read_kernel(&d, @sizeOf(c_ulong), ctx.arg1_ptr());
                return if (r != 0) error.READ_KERN else d;
            } else return @ptrCast(*REGS, self).arg1_ptr().*;
        }

        pub fn arg2(self: *Self) !c_ulong {
            if (LINUX_HAS_SYSCALL_WRAPPER) {
                const ctx = @intToPtr(*REGS, @ptrCast(*REGS, self).arg0_ptr().*);
                var d: c_ulong = undefined;
                const r = helpers.probe_read_kernel(&d, @sizeOf(c_ulong), ctx.arg2_ptr());
                return if (r != 0) error.READ_KERN else d;
            } else return @ptrCast(*REGS, self).arg2_ptr().*;
        }

        pub fn arg3(self: *Self) !c_ulong {
            if (LINUX_HAS_SYSCALL_WRAPPER) {
                const ctx = @intToPtr(*REGS, @ptrCast(*REGS, self).arg0_ptr().*);
                var d: c_ulong = undefined;
                const r = helpers.probe_read_kernel(&d, @sizeOf(c_ulong), ctx.arg3_ptr(true));
                return if (r != 0) error.READ_KERN else d;
            } else return @ptrCast(*REGS, self).arg3_ptr(true).*;
        }

        pub fn arg4(self: *Self) !c_ulong {
            if (LINUX_HAS_SYSCALL_WRAPPER) {
                const ctx = @intToPtr(*REGS, @ptrCast(*REGS, self).arg0_ptr().*);
                var d: c_ulong = undefined;
                const r = helpers.probe_read_kernel(&d, @sizeOf(c_ulong), ctx.arg4_ptr());
                return if (r != 0) error.READ_KERN else d;
            } else return @ptrCast(*REGS, self).arg4_ptr().*;
        }

        pub fn ret(self: *Self) c_ulong {
            return @ptrCast(*REGS, self).ret_ptr().*;
        }
    };
}
