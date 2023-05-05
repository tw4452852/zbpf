const std = @import("std");
const builtin = @import("builtin");
const fs = std.fs;
const Builder = std.Build;

const debugging = true;

fn create_bpf_prog(ctx: *const Ctx, src_path: ?[]const u8) *std.build.CompileStep {
    const name = fs.path.stem(src_path orelse "?");

    const prog = ctx.b.addObject(.{
        .name = name,
        .root_source_file = if (src_path) |path| .{
            .path = path,
        } else null,
        .target = .{
            .cpu_arch = switch ((ctx.target.cpu_arch orelse builtin.cpu.arch).endian()) {
                .Big => .bpfeb,
                .Little => .bpfel,
            },
            .os_tag = .freestanding,
        },
        .optimize = .ReleaseFast,
    });
    prog.addModule("bpf", ctx.bpf);
    prog.linkLibC();

    if (debugging) {
        prog.emit_llvm_ir = .{
            .emit_to = std.fmt.allocPrint(ctx.b.allocator, "/tmp/{s}.ir", .{name}) catch unreachable,
        };
    }

    return prog;
}

fn create_mounting_tracefs_step(b: *Builder) *Builder.Step {
    const S = struct {
        fn make(s: *Builder.Step, _: *std.Progress.Node) !void {
            fs.cwd().makeDir("src/bpf/tracefs") catch |e| if (e != std.os.MakeDirError.PathAlreadyExists) return s.fail("failed to create mounting dir: {s}", .{@errorName(e)});
            const ret = std.os.linux.getErrno(std.os.linux.mount("zbpf", "src/bpf/tracefs", "tracefs", 0, 0));
            if (ret != .SUCCESS and ret != .BUSY) {
                return s.fail("failed to mount tracefs: {s}", .{@tagName(ret)});
            }
        }
    };
    const s = b.allocator.create(Builder.Step) catch @panic("OOM");
    s.* = Builder.Step.init(.{
        .id = .custom,
        .name = "mount tracefs",
        .owner = b,
        .makeFn = S.make,
    });
    return s;
}

fn create_vmlinux(b: *Builder, target: std.zig.CrossTarget, optimize: std.builtin.Mode, libbpf: *std.build.CompileStep) *Builder.Module {
    const exe = b.addExecutable(.{
        .name = "vmlinux_dumper",
        .root_source_file = .{ .path = "src/vmlinux_dumper/main.zig" },
        .target = target,
        .optimize = optimize,
    });
    exe.linkLibrary(libbpf);
    exe.linkLibC();
    exe.addIncludePath("external/libbpf/src");

    const run_exe = b.addRunArtifact(exe);
    const stdout = run_exe.captureStdOut();
    const vmlinux_h = b.addInstallFile(stdout, "vmlinux.h");
    const zigify = b.addTranslateC(.{
        .source_file = .{ .path = vmlinux_h.dest_builder.getInstallPath(vmlinux_h.dir, vmlinux_h.dest_rel_path) },
        .target = target,
        .optimize = optimize,
    });
    zigify.step.dependOn(&vmlinux_h.step);
    return b.addModule("vmlinux", .{ .source_file = .{ .generated = &zigify.output_file } });
}

fn create_bpf(b: *Builder, target: std.zig.CrossTarget, optimize: std.builtin.Mode, libbpf: *std.build.CompileStep) *Builder.Module {
    return b.addModule("bpf", .{
        .source_file = .{ .path = "src/bpf/root.zig" },
        .dependencies = &.{.{ .name = "vmlinux", .module = create_vmlinux(b, target, optimize, libbpf) }},
    });
}

const Ctx = struct {
    b: *Builder,
    target: std.zig.CrossTarget,
    optimize: std.builtin.Mode,
    bpf: *Builder.Module,
    libbpf_step: *std.build.CompileStep,
};

pub fn build(b: *Builder) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // build libbpf
    const libbpf_dep = b.dependency("libbpf", .{
        .optimize = optimize,
        .target = target,
    });
    const libbpf = libbpf_dep.artifact("bpf");

    // build bpf package
    const bpf = create_bpf(b, target, optimize, libbpf);

    const ctx = Ctx{
        .b = b,
        .target = target,
        .optimize = optimize,
        .bpf = bpf,
        .libbpf_step = libbpf,
    };

    // build bpf program
    const bpf_src = b.option([]const u8, "bpf", "bpf program source path");
    const prog = create_bpf_prog(&ctx, bpf_src);

    const exe_src = b.option([]const u8, "main", "main executable source path");
    const exe = b.addExecutable(.{
        .name = "zbpf",
        .root_source_file = if (exe_src) |p| .{ .path = p } else null,
        .target = target,
        .optimize = optimize,
    });
    exe.addAnonymousModule("@bpf_prog", .{
        .source_file = prog.getOutputSource(),
    });

    exe.installLibraryHeaders(libbpf);
    exe.linkLibrary(libbpf);
    exe.linkLibC();
    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    // This allows the user to pass arguments to the application in the build
    // command itself, like this: `zig build run -- arg1 arg2 etc`
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }
    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);

    // Creates a step for unit testing.
    const exe_tests = b.addTest(.{
        .root_source_file = .{ .path = "src/tests/root.zig" },
        .target = target,
        .optimize = optimize,
    });
    exe_tests.filter = b.option([]const u8, "test", "test filter");
    exe_tests.linkLibrary(libbpf);
    exe_tests.linkLibC();
    exe_tests.addIncludePath("external/libbpf/src");
    const install_test = b.addInstallArtifact(exe_tests);

    // Create bpf programs for test
    var sample_dir = try fs.cwd().openIterableDir("samples", .{});
    defer sample_dir.close();
    var it = sample_dir.iterate();
    while (try it.next()) |entry| {
        const bpf_prog = create_bpf_prog(&ctx, try fs.path.join(b.allocator, &[_][]const u8{ "samples", entry.name }));
        exe_tests.addAnonymousModule(try std.fmt.allocPrint(b.allocator, "@{s}", .{fs.path.stem(entry.name)}), .{
            .source_file = bpf_prog.getOutputSource(),
        });
    }

    const run_test_step = b.step("test", "Build unit tests");
    run_test_step.dependOn(&install_test.step);
}
