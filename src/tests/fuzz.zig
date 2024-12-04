const std = @import("std");
const build_options = @import("@build_options");
const testing = std.testing;
const allocator = testing.allocator;
const print = std.debug.print;
const vmlinux = @import("vmlinux");

const Case = struct {
    name: []const u8,
    argn: usize,
    has_return_value: bool,
    skip: bool,
    index: usize,
};

test "trace_syscalls" {
    var buf: [256]u8 = undefined;
    const ksyscalls = vmlinux.kernel_syscalls;
    const decls = @typeInfo(ksyscalls).@"struct".decls;

    const cases = blk: {
        var array: [decls.len]Case = undefined;

        inline for (decls, 0..) |decl, i| {
            const f = @typeInfo(@field(ksyscalls, decl.name));

            array[i] = .{
                .name = decl.name,
                .argn = f.@"fn".params.len,
                .has_return_value = f.@"fn".return_type.? != void,
                .skip = false,
                .index = i,
            };
        }

        break :blk array;
    };

    const concurrency = 8;
    var it = std.mem.window(Case, &cases, concurrency, concurrency);
    var queue = std.mem.zeroes([concurrency]struct {
        index: usize,
        child_opt: ?std.process.Child,
    });
    while (it.next()) |batch| {
        for (&queue) |*entry| {
            if (entry.child_opt) |*child| {
                const term = try child.wait();
                if (term.Exited != 0) {
                    print("syscall {s}: {} params, {s} return value failed\n", .{ cases[entry.index].name, cases[entry.index].argn, if (cases[entry.index].has_return_value) "with" else "without" });
                }
                try testing.expectEqual(0, term.Exited);

                entry.index = 0;
                entry.child_opt = null;
            }
        }

        for (batch, 0..) |case, i| {
            const specifier = try std.fmt.bufPrintZ(&buf, "-Dsyscall={s[name]}:{s[arg0]}{s[arg1]}{s[arg2]}{s[arg3]}{s[arg4]}{s[ret]}", .{
                .name = case.name,
                .arg0 = if (case.argn > 0) "arg0" else "",
                .arg1 = if (case.argn > 1) ",arg1" else "",
                .arg2 = if (case.argn > 2) ",arg2" else "",
                .arg3 = if (case.argn > 3) ",arg3" else "",
                .arg4 = if (case.argn > 4) ",arg4" else "",
                .ret = if (!case.has_return_value) "" else if (case.argn > 0) ",ret" else "ret",
            });
            var child = std.process.Child.init(&.{ build_options.zig_exe, "build", "trace", "-Dinstall=false", specifier }, allocator);
            try child.spawn();

            queue[i] = .{ .child_opt = child, .index = case.index };
        }
    }
}

test "trace_kfuncs" {
    var buf: [256]u8 = undefined;
    const kfuncs = vmlinux.kernel_funcs;
    const decls = @typeInfo(kfuncs).@"struct".decls;

    @setEvalBranchQuota(1000000);
    const cases = blk: {
        var array: [decls.len]Case = undefined;

        inline for (decls, 0..) |decl, i| {
            const f = @typeInfo(@typeInfo(@field(kfuncs, decl.name)).pointer.child);

            var skip = false;
            // https://github.com/tw4452852/zbpf/issues/10
            inline for (f.@"fn".params) |param| {
                const T = param.type.?;
                if (@typeInfo(T) == .@"struct") {
                    skip = true;
                    break;
                }
            }
            if (f.@"fn".return_type) |T| {
                if (@typeInfo(T) == .@"struct") {
                    skip = true;
                }
            }

            array[i] = .{
                .name = decl.name,
                .argn = f.@"fn".params.len,
                .has_return_value = f.@"fn".return_type.? != void,
                .skip = skip,
                .index = i,
            };
        }

        break :blk array;
    };

    const concurrency = 8;
    var it = std.mem.window(Case, &cases, concurrency, concurrency);
    var queue = std.mem.zeroes([concurrency]struct {
        index: usize,
        child_opt: ?std.process.Child,
    });
    while (it.next()) |batch| {
        for (&queue) |*entry| {
            if (entry.child_opt) |*child| {
                const term = try child.wait();
                if (term.Exited != 0) {
                    print("{s}: {} params, {s} return value\n", .{ cases[entry.index].name, cases[entry.index].argn, if (cases[entry.index].has_return_value) "with" else "without" });
                }
                try testing.expectEqual(0, term.Exited);

                entry.index = 0;
                entry.child_opt = null;
            }
        }

        for (batch, 0..) |case, i| {
            if (case.skip) continue;

            const specifier = try std.fmt.bufPrintZ(&buf, "-Dkprobe={s[name]}:{s[arg0]}{s[arg1]}{s[arg2]}{s[arg3]}{s[arg4]}{s[ret]}", .{
                .name = case.name,
                .arg0 = if (case.argn > 0) "arg0" else "",
                .arg1 = if (case.argn > 1) ",arg1" else "",
                .arg2 = if (case.argn > 2) ",arg2" else "",
                .arg3 = if (case.argn > 3) ",arg3" else "",
                .arg4 = if (case.argn > 4) ",arg4" else "",
                .ret = if (!case.has_return_value) "" else if (case.argn > 0) ",ret" else "ret",
            });
            var child = std.process.Child.init(&.{ build_options.zig_exe, "build", "trace", "-Dinstall=false", specifier }, allocator);
            try child.spawn();

            queue[i] = .{ .child_opt = child, .index = case.index };
        }
    }
}
