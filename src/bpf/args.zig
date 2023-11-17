const vmlinux = @import("vmlinux");
const std = @import("std");
const StructField = std.builtin.Type.StructField;
const helpers = std.os.linux.BPF.kern.helpers;
const exit = @import("root.zig").exit;

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

const in_bpf_program = switch (@import("builtin").cpu.arch) {
    .bpfel, .bpfeb => true,
    else => false,
};

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

pub const REGS = extern struct {
    const Self = @This();
    impl: switch (arch) {
        .x86, .x86_64, .arm => vmlinux.pt_regs,
        .aarch64 => vmlinux.user_pt_regs,
        else => @panic("toto"),
    },

    pub fn arg0_ptr(self: *Self) *c_ulong {
        return switch (arch) {
            .x86_64 => &self.impl.di,
            .x86 => &self.impl.eax,
            .arm => &self.impl.uregs[0],
            .aarch64 => &self.impl.regs[0],
            else => {},
        };
    }

    pub fn arg1_ptr(self: *Self) *c_ulong {
        return switch (arch) {
            .x86_64 => &self.impl.si,
            .x86 => &self.impl.edx,
            .arm => &self.impl.uregs[1],
            .aarch64 => &self.impl.regs[1],
            else => {},
        };
    }

    pub fn arg2_ptr(self: *Self) *c_ulong {
        return switch (arch) {
            .x86_64 => &self.impl.dx,
            .x86 => &self.impl.ecx,
            .arm => &self.impl.uregs[2],
            .aarch64 => &self.impl.regs[2],
            else => {},
        };
    }

    pub fn arg3_ptr(self: *Self, for_syscall: bool) *c_ulong {
        return switch (arch) {
            .x86_64 => if (for_syscall) &self.impl.r10 else &self.impl.cx,
            .x86 => @compileError(std.fmt.comptimePrint("not support arg3 on i386", .{})),
            .arm => &self.impl.uregs[3],
            .aarch64 => &self.impl.regs[3],
            else => {},
        };
    }

    pub fn arg4_ptr(self: *Self) *c_ulong {
        return switch (arch) {
            .x86_64 => &self.impl.r8,
            .x86 => @compileError(std.fmt.comptimePrint("not support arg4 on i386", .{})),
            .arm => &self.impl.uregs[4],
            .aarch64 => &self.impl.regs[4],
            else => {},
        };
    }

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

pub inline fn is_pointer(comptime typ: type) bool {
    const ti = @typeInfo(typ);
    return ti == .Pointer or (ti == .Optional and @typeInfo(ti.Optional.child) == .Pointer);
}

pub fn cast(comptime T: type, rc: c_ulong) T {
    if (is_pointer(T)) return @ptrFromInt(rc);

    const ti = @typeInfo(T);
    if (ti == .Int) {
        if (ti.Int.signedness == .signed) {
            return @truncate(@as(c_long, @bitCast(rc)));
        }
        return @truncate(rc);
    }

    return rc;
}

pub fn PT_REGS(comptime func_name: []const u8, comptime for_syscall: bool) type {
    const f = @typeInfo(@TypeOf(@field(vmlinux, func_name)));

    return opaque {
        const Self = @This();

        pub inline fn get_regs(self: *Self) *REGS {
            return @alignCast(@ptrCast(self));
        }

        pub usingnamespace if (f.Fn.params.len < 1) struct {} else struct {
            const RET = f.Fn.params[0].type.?;

            pub fn arg0(self: *Self) RET {
                if (!in_bpf_program) {
                    return cast(RET, self.get_regs().arg0_ptr().*);
                } else {
                    var ret: RET = undefined;
                    const err = helpers.probe_read_kernel(@ptrCast(&ret), @sizeOf(RET), self.get_regs().arg0_ptr());
                    return if (err != 0) exit(@src(), err) else ret;
                }
            }
        };

        pub usingnamespace if (f.Fn.params.len < 2) struct {} else struct {
            const RET = f.Fn.params[1].type.?;

            pub fn arg1(self: *Self) RET {
                if (!in_bpf_program) {
                    return cast(RET, self.get_regs().arg1_ptr().*);
                } else {
                    var ret: RET = undefined;
                    const err = helpers.probe_read_kernel(@ptrCast(&ret), @sizeOf(RET), self.get_regs().arg1_ptr());
                    return if (err != 0) exit(@src(), err) else ret;
                }
            }
        };

        pub usingnamespace if (f.Fn.params.len < 3) struct {} else struct {
            const RET = f.Fn.params[2].type.?;

            pub fn arg2(self: *Self) RET {
                if (!in_bpf_program) {
                    return cast(RET, self.get_regs().arg2_ptr().*);
                } else {
                    var ret: RET = undefined;
                    const err = helpers.probe_read_kernel(@ptrCast(&ret), @sizeOf(RET), self.get_regs().arg2_ptr());
                    return if (err != 0) exit(@src(), err) else ret;
                }
            }
        };

        pub usingnamespace if (f.Fn.params.len < 4) struct {} else struct {
            const RET = f.Fn.params[3].type.?;

            pub fn arg3(self: *Self) RET {
                if (!in_bpf_program) {
                    return cast(RET, self.get_regs().arg3_ptr(for_syscall).*);
                } else {
                    var ret: RET = undefined;
                    const err = helpers.probe_read_kernel(@ptrCast(&ret), @sizeOf(RET), self.get_regs().arg3_ptr(for_syscall));
                    return if (err != 0) exit(@src(), err) else ret;
                }
            }
        };

        pub usingnamespace if (f.Fn.params.len < 5) struct {} else struct {
            const RET = f.Fn.params[4].type.?;

            pub fn arg4(self: *Self) RET {
                if (!in_bpf_program) {
                    return cast(RET, self.get_regs().arg4_ptr().*);
                } else {
                    var ret: RET = undefined;
                    const err = helpers.probe_read_kernel(@ptrCast(&ret), @sizeOf(RET), self.get_regs().arg4_ptr());
                    return if (err != 0) exit(@src(), err) else ret;
                }
            }
        };

        pub usingnamespace if (f.Fn.return_type.? == void) struct {} else struct {
            const RET = f.Fn.return_type.?;

            pub fn ret(self: *Self) RET {
                if (!in_bpf_program) {
                    return cast(RET, self.get_regs().ret_ptr().*);
                } else {
                    var v: RET = undefined;
                    const err = helpers.probe_read_kernel(@ptrCast(&v), @sizeOf(RET), self.get_regs().ret_ptr());
                    return if (err != 0) exit(@src(), err) else v;
                }
            }
        };
    };
}

pub fn SYSCALL(comptime name: []const u8) type {
    const func_name = "sys_" ++ name;
    if (!@hasDecl(vmlinux, func_name))
        @compileError(std.fmt.comptimePrint("can't get function prototype for syscall {s} on {}", .{ name, arch }));
    const f = @typeInfo(@TypeOf(@field(vmlinux, func_name)));
    const T = PT_REGS(func_name, true);

    return opaque {
        const Self = @This();

        pub inline fn get_arg_ctx(self: *Self) *T {
            if (!in_bpf_program) return @ptrCast(self);

            return if (LINUX_HAS_SYSCALL_WRAPPER)
                @ptrFromInt(@as(*REGS, @alignCast(@ptrCast(self))).arg0_ptr().*)
            else
                @ptrCast(self);
        }

        pub usingnamespace if (f.Fn.params.len < 1) struct {} else struct {
            const RET = f.Fn.params[0].type.?;

            pub fn arg0(self: *Self) RET {
                return self.get_arg_ctx().arg0();
            }
        };

        pub usingnamespace if (f.Fn.params.len < 2) struct {} else struct {
            const RET = f.Fn.params[1].type.?;

            pub fn arg1(self: *Self) RET {
                return self.get_arg_ctx().arg1();
            }
        };

        pub usingnamespace if (f.Fn.params.len < 3) struct {} else struct {
            const RET = f.Fn.params[2].type.?;

            pub fn arg2(self: *Self) RET {
                return self.get_arg_ctx().arg2();
            }
        };

        pub usingnamespace if (f.Fn.params.len < 4) struct {} else struct {
            const RET = f.Fn.params[3].type.?;

            pub fn arg3(self: *Self) RET {
                return self.get_arg_ctx().arg3();
            }
        };

        pub usingnamespace if (f.Fn.params.len < 5) struct {} else struct {
            const RET = f.Fn.params[4].type.?;

            pub fn arg4(self: *Self) RET {
                return self.get_arg_ctx().arg4();
            }
        };

        pub usingnamespace if (f.Fn.return_type.? == void) struct {} else struct {
            const RET = f.Fn.return_type.?;

            pub fn ret(self: *Self) RET {
                return @as(*T, @ptrCast(self)).ret();
            }
        };
    };
}

pub const TRACE_RECORD = extern struct {
    id: u32,
    tpid: u64,
    regs: REGS,
};
