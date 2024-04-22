const std = @import("std");
const builtin = @import("builtin");
const fs = std.fs;

fn create_bpf_prog(ctx: *const Ctx, src_path: []const u8) *std.Build.Step.Compile {
    const name = fs.path.stem(src_path);

    const prog = ctx.b.addObject(.{
        .name = name,
        .root_source_file = .{
            .path = src_path,
        },
        .target = ctx.b.resolveTargetQuery(.{
            .cpu_arch = switch (ctx.target.result.cpu.arch.endian()) {
                .big => .bpfeb,
                .little => .bpfel,
            },
            .os_tag = .freestanding,
        }),
        .optimize = .ReleaseFast,
    });
    prog.root_module.strip = false;
    prog.root_module.addImport("bpf", ctx.bpf);
    prog.root_module.addImport("build_options", ctx.bpf);
    prog.root_module.addOptions("build_options", ctx.build_options);

    return prog;
}

fn create_libbpf(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode) *std.Build.Step.Compile {
    return b.dependency("libbpf", .{
        .target = target,
        .optimize = optimize,
        .zig_wa = true,
    }).artifact("bpf");
}

fn create_vmlinux(b: *std.Build) *std.Build.Module {
    // build for native
    const target = b.host;
    const optimize: std.builtin.OptimizeMode = .ReleaseFast;

    const libbpf = create_libbpf(b, target, optimize);
    const exe = b.addExecutable(.{
        .name = "vmlinux_dumper",
        .root_source_file = .{ .path = "src/vmlinux_dumper/main.zig" },
        .target = target,
        .optimize = optimize,
    });
    exe.linkLibrary(libbpf);
    exe.linkLibC();
    b.installArtifact(exe);

    const run_exe = b.addRunArtifact(exe);
    const vmlinux_bin = b.option([]const u8, "vmlinux", "vmlinux binary used for BTF generation");
    if (vmlinux_bin) |vmlinux| run_exe.addArg(vmlinux);
    const stdout = run_exe.captureStdOut();
    const vmlinux_h = b.addInstallFile(stdout, "vmlinux.h");
    const zigify = b.addTranslateC(.{
        .root_source_file = .{ .path = b.getInstallPath(vmlinux_h.dir, vmlinux_h.dest_rel_path) },
        .target = target,
        .optimize = optimize,
    });
    zigify.addIncludeDir("src/vmlinux_dumper");
    zigify.step.dependOn(&vmlinux_h.step);
    return b.addModule("vmlinux", .{ .root_source_file = .{ .generated = &zigify.output_file } });
}

fn create_bpf(b: *std.Build, vmlinux: *std.Build.Module) *std.Build.Module {
    return b.addModule("bpf", .{
        .root_source_file = .{ .path = "src/bpf/root.zig" },
        .imports = &.{.{ .name = "vmlinux", .module = vmlinux }},
    });
}

const Ctx = struct {
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    vmlinux: *std.Build.Module,
    bpf: *std.Build.Module,
    libbpf_step: *std.Build.Step.Compile,
    build_options: *std.Build.Step.Options,
};

pub fn build(b: *std.Build) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const libbpf = create_libbpf(b, target, optimize);

    const vmlinux = create_vmlinux(b);

    const bpf = create_bpf(b, vmlinux);

    const build_options = b.addOptions();
    const debugging = if (b.option(bool, "debug", "enable debugging log")) |v| v else false;
    const kprobes = if (b.option([]const []const u8, "kprobe", "the traced kernel function name")) |v| v else &.{};
    const syscalls = if (b.option([]const []const u8, "syscall", "the traced syscall name")) |v| v else &.{};
    build_options.addOption(@TypeOf(debugging), "debug", debugging);
    build_options.addOption(@TypeOf(kprobes), "kprobes", kprobes);
    build_options.addOption(@TypeOf(syscalls), "syscalls", syscalls);

    const ctx = Ctx{
        .b = b,
        .target = target,
        .optimize = optimize,
        .bpf = bpf,
        .libbpf_step = libbpf,
        .build_options = build_options,
        .vmlinux = vmlinux,
    };

    // default bpf program
    const bpf_src = if (b.option([]const u8, "bpf", "bpf program source path")) |v| v else "samples/perf_event.zig";
    const exe_src = if (b.option([]const u8, "main", "main executable source path")) |v| v else "src/hello.zig";
    try create_target_step(&ctx, exe_src, bpf_src, null);

    try create_target_step(&ctx, "src/trace.zig", "src/trace.bpf.zig", "trace");

    try create_test_step(&ctx);

    try create_docs_step(&ctx);
}

fn create_target_step(ctx: *const Ctx, main_path: []const u8, prog_path: []const u8, exe_name: ?[]const u8) !void {
    const prog = create_bpf_prog(ctx, prog_path);

    const exe = ctx.b.addExecutable(.{
        .name = if (exe_name) |name| name else "zbpf",
        .root_source_file = .{ .path = main_path },
        .target = ctx.target,
        .optimize = ctx.optimize,
    });
    exe.root_module.addAnonymousImport("@bpf_prog", .{
        .root_source_file = prog.getEmittedBin(),
    });
    exe.root_module.addImport("bpf", ctx.bpf);
    exe.root_module.addImport("vmlinux", ctx.vmlinux);
    exe.root_module.addOptions("build_options", ctx.build_options);

    exe.linkLibrary(ctx.libbpf_step);
    exe.linkLibC();

    // if executable is not named, it is default target
    // otherwise, create a step for it
    if (exe_name) |name| {
        const install_exe = ctx.b.addInstallArtifact(exe, .{});
        var buf: [64]u8 = undefined;
        const description = try std.fmt.bufPrint(&buf, "Build {s}", .{name});
        const build_step = ctx.b.step(name, description);
        build_step.dependOn(&install_exe.step);
    } else {
        ctx.b.installArtifact(exe);
    }
}

fn create_test_step(ctx: *const Ctx) !void {
    // Creates a step for unit testing.
    const exe_tests = ctx.b.addTest(.{
        .root_source_file = .{ .path = "src/tests/root.zig" },
        .target = ctx.target,
        .optimize = ctx.optimize,
        .filter = ctx.b.option([]const u8, "test", "test filter"),
    });
    exe_tests.linkLibrary(ctx.libbpf_step);
    exe_tests.root_module.addImport("bpf", ctx.bpf);
    exe_tests.linkLibC();
    const install_test = ctx.b.addInstallArtifact(exe_tests, .{});

    // Create bpf programs for test
    var sample_dir = try fs.cwd().openDir("samples", .{ .iterate = true });
    defer sample_dir.close();
    var it = sample_dir.iterate();
    while (try it.next()) |entry| {
        const bpf_prog = create_bpf_prog(ctx, try fs.path.join(ctx.b.allocator, &[_][]const u8{ "samples", entry.name }));
        exe_tests.root_module.addAnonymousImport(try std.fmt.allocPrint(ctx.b.allocator, "@{s}", .{fs.path.stem(entry.name)}), .{
            .root_source_file = bpf_prog.getEmittedBin(),
        });
    }

    // add debug option to test
    exe_tests.root_module.addOptions("build_options", ctx.build_options);

    const build_test_step = ctx.b.step("test", "Build unit tests");
    build_test_step.dependOn(&install_test.step);
}

fn create_docs_step(ctx: *const Ctx) !void {
    const exe = ctx.b.addObject(.{
        .name = "docs",
        .root_source_file = .{ .path = "src/docs/docs.zig" },
        .target = ctx.target,
        .optimize = ctx.optimize,
    });

    const dumb_vmlinux = ctx.b.addModule("dumb_vmlinux", .{ .root_source_file = .{ .path = "src/docs/dummy_vmlinux.zig" } });
    const bpf = create_bpf(ctx.b, dumb_vmlinux);
    exe.root_module.addImport("bpf", bpf);

    const install_docs = ctx.b.addInstallDirectory(.{
        .source_dir = exe.getEmittedDocs(),
        .install_dir = .prefix,
        .install_subdir = "docs",
    });

    const step = ctx.b.step("docs", "generate documents");
    step.dependOn(&install_docs.step);
}
