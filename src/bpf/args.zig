const vmlinux = @import("vmlinux");
const std = @import("std");
const StructField = std.builtin.Type.StructField;

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

pub fn PT_REGS(comptime func_name: []const u8) type {
    const f = @typeInfo(@TypeOf(@field(vmlinux, "_zig_" ++ func_name)));
    const S = if (@hasDecl(vmlinux, "user_pt_regs")) vmlinux.user_pt_regs else vmlinux.pt_regs;

    return opaque {
        const Self = @This();

        pub usingnamespace if (f.Fn.params.len < 1) struct {} else struct {
            pub fn arg0(self: *Self) f.Fn.params[0].type.? {
                const pt = @ptrCast(*S, @alignCast(@alignOf(S), self));
                return if (@hasField(S, "di"))
                    pt.di
                else if (@hasField(S, "eax"))
                    pt.eax
                else if (@hasField(S, "rdi"))
                    pt.rdi
                else if (@hasField(S, "uregs"))
                    pt.uregs[0]
                else if (@hasField(S, "regs"))
                    pt.regs[0]
                else
                    @compileError(std.fmt.comptimePrint("{s}: can't determine arg0 {any}'s type from {any}", .{ func_name, @typeInfo(f.Fn.params[0].type.?), @typeInfo(S).Struct.fields }));
            }
        };

        pub usingnamespace if (f.Fn.params.len < 2) struct {} else struct {
            pub fn arg1(self: *Self) f.Fn.params[1].type.? {
                const pt = @ptrCast(*S, @alignCast(@alignOf(S), self));
                return if (@hasField(S, "si"))
                    pt.si
                else if (@hasField(S, "edx"))
                    pt.edx
                else if (@hasField(S, "rsi"))
                    pt.rsi
                else if (@hasField(S, "uregs"))
                    pt.uregs[1]
                else if (@hasField(S, "regs"))
                    pt.regs[1]
                else
                    @compileError(std.fmt.comptimePrint("{s}: can't determine arg1 {any}'s type from {any}", .{ func_name, @typeInfo(f.Fn.params[1].type.?), @typeInfo(S).Struct.fields }));
            }
        };

        pub usingnamespace if (f.Fn.params.len < 3) struct {} else struct {
            pub fn arg2(self: *Self) f.Fn.params[2].type.? {
                const pt = @ptrCast(*S, @alignCast(@alignOf(S), self));
                return if (@hasField(S, "dx"))
                    pt.dx
                else if (@hasField(S, "ecx"))
                    pt.ecx
                else if (@hasField(S, "rdx"))
                    pt.rdx
                else if (@hasField(S, "uregs"))
                    pt.uregs[2]
                else if (@hasField(S, "regs"))
                    pt.regs[2]
                else
                    @compileError(std.fmt.comptimePrint("{s}: can't determine arg2 {any}'s type from {s}", .{ func_name, @typeInfo(f.Fn.params[2].type.?), @typeInfo(S).Struct.fields }));
            }
        };

        pub usingnamespace if (f.Fn.params.len < 4) struct {} else struct {
            pub fn arg3(self: *Self) f.Fn.params[3].type.? {
                const pt = @ptrCast(*S, @alignCast(@alignOf(S), self));
                return if (@hasField(S, "cx"))
                    pt.cx
                else if (@hasField(S, "rcx"))
                    pt.rcx
                else if (@hasField(S, "uregs"))
                    pt.uregs[3]
                else if (@hasField(S, "regs"))
                    pt.regs[3]
                else
                    @compileError(std.fmt.comptimePrint("{s}: can't determine arg3 {any}'s type from {any}", .{ func_name, @typeInfo(f.Fn.params[3].type.?), @typeInfo(S).Struct.fields }));
            }
        };

        pub usingnamespace if (f.Fn.params.len < 5) struct {} else struct {
            pub fn arg4(self: *Self) f.Fn.params[4].type.? {
                const pt = @ptrCast(*S, @alignCast(@alignOf(S), self));
                return if (@hasField(S, "r8"))
                    pt.r8
                else if (@hasField(S, "uregs"))
                    pt.uregs[4]
                else if (@hasField(S, "regs"))
                    pt.regs[4]
                else
                    @compileError(std.fmt.comptimePrint("{s}: can't determine arg4 {any}'s type from {any}", .{ func_name, @typeInfo(f.Fn.params[4].type.?), @typeInfo(S).Struct.fields }));
            }
        };

        const RET = f.Fn.return_type.?;
        const ti = @typeInfo(RET);
        const is_pointer = ti == .Pointer or (ti == .Optional and @typeInfo(ti.Optional.child) == .Pointer);
        pub usingnamespace if (RET == void) struct {} else struct {
            pub fn ret(self: *Self) RET {
                const pt = @ptrCast(*S, @alignCast(@alignOf(S), self));
                return if (@hasField(S, "ax"))
                    if (!is_pointer) @intCast(RET, pt.ax) else pt.ax
                else if (@hasField(S, "eax"))
                    if (!is_pointer) @intCast(RET, pt.eax) else pt.eax
                else if (@hasField(S, "rax"))
                    if (!is_pointer) @intCast(RET, pt.rax) else pt.rax
                else if (@hasField(S, "uregs"))
                    if (!is_pointer) @intCast(RET, pt.uregs[0]) else pt.uregs[0]
                else if (@hasField(S, "regs"))
                    if (!is_pointer) @intCast(RET, pt.regs[0]) else pt.regs[0]
                else
                    @compileError(std.fmt.comptimePrint("{s}: can't determine return {any}'s type from {any}", .{ func_name, ti, @typeInfo(S).Struct.fields }));
            }
        };
    };
}
