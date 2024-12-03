const std = @import("std");
const bpf = @import("bpf");
const helpers = std.os.linux.BPF.kern.helpers;

const in_bpf_program = switch (@import("builtin").cpu.arch) {
    .bpfel, .bpfeb => true,
    else => false,
};

/// Structure passing from BPF side to userspace for tracing.
pub const TRACE_RECORD = extern struct {
    id: u32,
    entry: bool,
    tpid: u64,
    stack_id: isize,
};

inline fn is_string(T: type) bool {
    return T == *u8;
}
const String = [64]u8;

inline fn copy_properly(dst: usize, src: usize, comptime size: usize, comptime is_str: bool) void {
    const n: isize = @bitCast(src);
    if (is_str) {
        if (n < 0) {
            _ = helpers.probe_read_kernel_str(@ptrFromInt(dst), size, @ptrFromInt(src));
        } else {
            _ = helpers.probe_read_user_str(@ptrFromInt(dst), size, @ptrFromInt(src));
        }
    } else {
        if (n < 0) {
            _ = helpers.probe_read_kernel(@ptrFromInt(dst), size, @ptrFromInt(src));
        } else {
            _ = helpers.probe_read_user(@ptrFromInt(dst), size, @ptrFromInt(src));
        }
    }
}

/// Argument specifier format as follow:
/// func_name[:argN][.field_name][/format_placeholder]
///
/// :argN: N is in the range of 0..function's parameter number,
/// if function doesn't have paramter, this part shouldn't be specified.
/// .field_name: field name in the current structure, any number of nest is possible.
/// /format_placeholder: All zig's fmt placeholders are allowed,
/// if not specified, {s} will be used for string, {any} for others.
pub fn Arg(comptime name: []const u8, comptime is_syscall: bool) type {
    const F = if (is_syscall) bpf.Ksyscall{ .name = name } else bpf.Kprobe{ .name = name };

    return struct {
        pub fn Field(comptime specifier: []const u8) type {
            // trim trailing placeholder if any
            const slash = comptime std.mem.lastIndexOfScalar(u8, specifier, '/');
            comptime var it = std.mem.tokenizeScalar(u8, specifier[0..if (slash) |si| si else specifier.len], '.');
            const argN = comptime it.next().?;
            comptime var FT: type = @TypeOf(@field(F.Ctx(), argN)(@ptrFromInt(1)));

            if (is_string(FT)) return String;

            var ti = @typeInfo(FT);
            inline while (comptime it.next()) |field_name| : (ti = @typeInfo(FT)) {
                if (ti == .optional) {
                    FT = ti.optional.child;
                    ti = @typeInfo(FT);
                }

                if (ti == .pointer) {
                    FT = ti.pointer.child;
                    ti = @typeInfo(FT);
                }
                if (ti == .@"struct") {
                    inline for (ti.@"struct".fields) |field| {
                        if (std.mem.eql(u8, field.name, field_name)) {
                            FT = field.type;
                            ti = @typeInfo(FT);
                            break;
                        }
                    } else @compileError("can't find field " ++ field_name ++ " in " ++ @typeName(FT));
                } else @compileError(@typeName(FT) ++ " is not a struct");

                if (is_string(FT)) return String;
            }
            return if (bpf.Args.is_pointer(FT))
                bpf.Args.deref_pointer(FT)
            else
                FT;
        }

        pub fn placeholder(comptime specifier: []const u8) []const u8 {
            // get user specified placeholder if any
            const user: ?[]const u8 = us: {
                const slash = comptime std.mem.lastIndexOfScalar(u8, specifier, '/');
                break :us if (slash) |si| specifier[si + 1 ..] else null;
            };

            return if (user) |ph| "{" ++ ph ++ "}" else ph: {
                const T = Field(specifier);
                break :ph if (T == String) "{s}" else "{any}";
            };
        }

        pub usingnamespace if (!in_bpf_program) struct {} else struct {
            pub fn copy(comptime specifier: []const u8, ctx: *anyopaque, dst: *[*c]u8) void {
                // trim trailing placeholder if any
                const slash = comptime std.mem.lastIndexOfScalar(u8, specifier, '/');
                comptime var it = std.mem.tokenizeScalar(u8, specifier[0..if (slash) |si| si else specifier.len], '.');
                const argN = comptime it.next().?;
                comptime var FT: type = @TypeOf(@field(F.Ctx(), argN)(@ptrFromInt(1)));
                const arg = @field(F.Ctx(), argN)(@ptrCast(ctx));
                //@compileLog(specifier, FT, Field(specifier));
                if (is_string(FT)) {
                    copy_properly(@intFromPtr(dst.*), @intFromPtr(arg), @sizeOf(String), true);
                    dst.* += @sizeOf(Field(specifier));
                    return;
                }

                comptime var ti = @typeInfo(FT);
                var src: usize = if (ti == .pointer) @intFromPtr(arg) else @intFromPtr(&arg);

                inline while (comptime it.next()) |field_name| {
                    if (ti == .optional) {
                        FT = ti.optional.child;
                        ti = @typeInfo(FT);
                    }
                    if (ti == .pointer) {
                        FT = ti.pointer.child;
                        ti = @typeInfo(FT);
                    }

                    // find and access field
                    comptime var field_offset: usize = 0;
                    if (ti != .@"struct") @compileError(@typeName(FT) ++ "is not a struct");
                    inline for (ti.@"struct".fields) |field| {
                        if (comptime std.mem.eql(u8, field.name, field_name)) {
                            field_offset = @offsetOf(FT, field_name);
                            FT = field.type;
                            ti = @typeInfo(FT);
                            break;
                        }
                    } else @compileError("can't find field " ++ field_name ++ " in " ++ @typeName(FT));

                    if (is_string(FT)) {
                        copy_properly(@intFromPtr(dst.*), src + field_offset, @sizeOf(String), true);
                        dst.* += @sizeOf(Field(specifier));
                        return;
                    }

                    if (ti == .pointer) {
                        var dst_p: usize = undefined;

                        copy_properly(@intFromPtr(&dst_p), src + field_offset, @sizeOf(usize), false);
                        src = dst_p;
                    } else src += field_offset;
                }

                copy_properly(@intFromPtr(dst.*), src, @sizeOf(Field(specifier)), is_string(FT));
                dst.* += @sizeOf(Field(specifier));
            }
        };
    };
}
