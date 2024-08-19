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

/// Return argument context according to the specified kernel function prototype.
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
            .layout = .@"extern",
            .is_tuple = false,
            .fields = fields,
            .decls = &.{},
        },
    });
}

/// Represent `struct pt_regs` for different architectures.
pub const REGS = extern struct {
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
    return ti == .Pointer or (ti == .Optional and @typeInfo(ti.Optional.child) == .Pointer);
}

/// Get the pointee type
pub inline fn deref_pointer(comptime typ: type) type {
    const ti = @typeInfo(typ);
    return switch (ti) {
        inline .Pointer => |info| return info.child,
        inline .Optional => |info| return @typeInfo(info.child).Pointer.child,
        else => @compileLog(ti),
    };
}

/// Cast `c_ulong` value into the corresponding type.
pub fn cast(comptime T: type, rc: c_ulong) T {
    if (is_pointer(T)) return @ptrFromInt(rc);

    const ti = @typeInfo(T);
    if (ti == .Int) {
        if (ti.Int.signedness == .signed) {
            return @truncate(@as(c_long, @bitCast(rc)));
        }
        return @truncate(rc);
    }

    if (T == bool) return rc == 1;

    return rc;
}

/// Return the actual type to retrive arguments for the specified kernel function.
/// As syscall function has different retrieving method than regular kernel function,
/// this will hide the underlying mechanism to provider a consistent API.
pub fn PT_REGS(comptime func_name: []const u8, comptime for_syscall: bool) type {
    const f = @typeInfo(@TypeOf(@field(vmlinux, func_name)));

    return opaque {
        const Self = @This();

        /// helper function to return the underlying `REG`.
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

        pub usingnamespace if (!in_bpf_program) struct {} else struct {
            pub fn extra_record_size() usize {
                comptime var size: usize = 0;

                if (f.Fn.params.len > 0 and is_pointer(f.Fn.params[0].type.?)) {
                    size += pointer_size(f.Fn.params[0].type.?, 0);
                }
                if (f.Fn.params.len > 1 and is_pointer(f.Fn.params[1].type.?)) {
                    size += pointer_size(f.Fn.params[1].type.?, 0);
                }
                if (f.Fn.params.len > 2 and is_pointer(f.Fn.params[2].type.?)) {
                    size += pointer_size(f.Fn.params[2].type.?, 0);
                }
                if (f.Fn.params.len > 3 and is_pointer(f.Fn.params[3].type.?)) {
                    size += pointer_size(f.Fn.params[3].type.?, 0);
                }
                if (f.Fn.params.len > 4 and is_pointer(f.Fn.params[4].type.?)) {
                    size += pointer_size(f.Fn.params[4].type.?, 0);
                }
                if (f.Fn.return_type.? != void and is_pointer(f.Fn.return_type.?)) {
                    size += pointer_size(f.Fn.return_type.?, 0);
                }

                return size;
            }

            fn pointer_size(comptime T: type, comptime level: usize) usize {
                // special case for char*
                if (T == [*c]const u8) {
                    return 64;
                }

                const Child = deref_pointer(T);
                comptime var size: usize = if (Child == anyopaque) 0 else @sizeOf(Child);
                // At most 2 levels deep
                if (level == 2) {
                    return size;
                }

                return switch (@typeInfo(Child)) {
                    inline .Pointer, .Optional => size + pointer_size(Child, level + 1),
                    inline .Struct => |info| blk: {
                        inline for (info.fields) |field| {
                            if (is_pointer(field.type)) {
                                size += pointer_size(field.type, level + 1);
                            }
                        }

                        break :blk size;
                    },
                    else => size,
                };
            }

            pub fn deep_copy_to_user(src: *const REGS, start: usize, entry: bool) REGS {
                var dst: REGS = src.*;
                var buf: [*c]u8 = @ptrFromInt(start);

                if (entry) {
                    if (f.Fn.params.len > 0 and is_pointer(f.Fn.params[0].type.?)) {
                        dst.arg0_ptr().* = dup_pointer(f.Fn.params[0].type.?, @ptrFromInt(dst.arg0_ptr().*), &buf, 0, start);
                    }
                    if (f.Fn.params.len > 1 and is_pointer(f.Fn.params[1].type.?)) {
                        dst.arg1_ptr().* = dup_pointer(f.Fn.params[1].type.?, @ptrFromInt(dst.arg1_ptr().*), &buf, 0, start);
                    }
                    if (f.Fn.params.len > 2 and is_pointer(f.Fn.params[2].type.?)) {
                        dst.arg2_ptr().* = dup_pointer(f.Fn.params[2].type.?, @ptrFromInt(dst.arg2_ptr().*), &buf, 0, start);
                    }
                    if (f.Fn.params.len > 3 and is_pointer(f.Fn.params[3].type.?)) {
                        dst.arg3_ptr().* = dup_pointer(f.Fn.params[3].type.?, @ptrFromInt(dst.arg3_ptr().*), &buf, 0, start);
                    }
                    if (f.Fn.params.len > 4 and is_pointer(f.Fn.params[4].type.?)) {
                        dst.arg4_ptr().* = dup_pointer(f.Fn.params[4].type.?, @ptrFromInt(dst.arg4_ptr().*), &buf, 0, start);
                    }
                } else {
                    if (f.Fn.return_type.? != void and is_pointer(f.Fn.return_type.?)) {
                        dst.ret_ptr().* = dup_pointer(f.Fn.return_type.?, @ptrFromInt(dst.ret_ptr().*), &buf, 0, start);
                    }
                }

                return dst;
            }

            fn dup_pointer(comptime T: type, src: T, buf: *[*c]u8, level: usize, start: usize) usize {
                // special case for char*
                if (T == [*c]const u8) {
                    const dst = buf.*;
                    const n = helpers.probe_read_str(dst, 64, src);
                    if (n < 0) {
                        return @intCast(n);
                    }
                    buf.* += @as(usize, @intCast(n));
                    return @intFromPtr(dst) - start;
                }

                const Child = deref_pointer(T);
                // *anyopaque
                if (Child == anyopaque) {
                    return @intFromPtr(src);
                }
                const dst: T = @alignCast(@ptrCast(buf.*));
                var ret = helpers.probe_read_kernel(dst, @sizeOf(Child), src);
                if (ret != 0) {
                    return @intCast(ret);
                }
                buf.* += @sizeOf(Child);

                // At most 2 levels deep
                if (level == 2) {
                    return @intFromPtr(dst) - start;
                }

                switch (@typeInfo(Child)) {
                    inline .Pointer => {
                        dst.* = dup_pointer(Child, src.*, buf, level + 1, start);
                    },
                    inline .Struct => |info| {
                        inline for (info.fields) |field| {
                            if (is_pointer(field.type)) {
                                const p = dup_pointer(field.type, @ptrFromInt(@intFromPtr(dst) + @offsetOf(Child, field.name)), buf, level + 1, start);
                                ret = helpers.probe_read(@ptrFromInt(@intFromPtr(dst) + @offsetOf(Child, field.name)), @sizeOf(field.type), &p);
                                if (ret != 0) {
                                    return @intCast(ret);
                                }
                            }
                        }
                    },
                    else => {},
                }

                return @intFromPtr(dst) - start;
            }
        };
    };
}

/// A Wrapper type for syscall arguments retrieving.
pub fn SYSCALL(comptime name: []const u8) type {
    const func_name = "sys_" ++ name;
    if (!@hasDecl(vmlinux, func_name))
        @compileError(std.fmt.comptimePrint("can't get function prototype for syscall {s} on {}", .{ name, arch }));
    const f = @typeInfo(@TypeOf(@field(vmlinux, func_name)));
    const T = PT_REGS(func_name, true);

    return opaque {
        const Self = @This();

        /// helper function to get underlying `PT_REGS`.
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

        pub usingnamespace if (!in_bpf_program) struct {} else struct {
            pub fn extra_record_size() usize {
                return T.extra_record_size();
            }

            pub fn deep_copy_to_user(src: *const REGS, start: usize, entry: bool) REGS {
                return T.deep_copy_to_user(src, start, entry);
            }
        };
    };
}

/// Structure passing from BPF side to userspace for tracing.
pub const TRACE_RECORD = extern struct {
    id: u32,
    entry: bool,
    tpid: u64,
    regs: REGS,
    extra_offset: usize,
    stack_id: isize,
};
