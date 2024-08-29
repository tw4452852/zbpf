const std = @import("std");
const builtin = @import("builtin");
const fs = std.fs;

var debugging = false;

fn create_bpf_prog(ctx: *const Ctx, src_path: []const u8) std.Build.LazyPath {
    const name = fs.path.stem(src_path);

    const prog = ctx.b.addObject(.{
        .name = name,
        .root_source_file = ctx.b.path(src_path),
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
    prog.root_module.addImport("vmlinux", ctx.vmlinux);
    prog.root_module.addOptions("build_options", ctx.build_options);

    const run_btf_sanitizer = ctx.b.addRunArtifact(ctx.btf_sanitizer);
    run_btf_sanitizer.addFileArg(prog.getEmittedBin());
    if (ctx.vmlinux_bin_path) |vmlinux| {
        run_btf_sanitizer.addPrefixedFileArg("-vmlinux", .{ .cwd_relative = vmlinux });
    }
    if (debugging) run_btf_sanitizer.addArg("-debug");
    return run_btf_sanitizer.addPrefixedOutputFileArg("-o", ctx.b.fmt("{s}_sanitized.o", .{name}));
}

fn create_libbpf(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode) *std.Build.Step.Compile {
    return b.dependency("libbpf", .{
        .target = target,
        .optimize = optimize,
    }).artifact("bpf");
}

fn create_vmlinux(b: *std.Build, libbpf: *std.Build.Step.Compile, vmlinux_bin: ?[]const u8) *std.Build.Module {
    // build for native
    const target = b.host;
    const optimize: std.builtin.OptimizeMode = .ReleaseFast;

    const exe = b.addExecutable(.{
        .name = "vmlinux_dumper",
        .root_source_file = b.path("src/vmlinux_dumper/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    exe.linkLibrary(libbpf);
    exe.linkLibC();
    b.installArtifact(exe);

    const run_exe = b.addRunArtifact(exe);

    if (vmlinux_bin) |vmlinux| run_exe.addPrefixedFileArg("-vmlinux", .{ .cwd_relative = vmlinux });
    if (debugging) run_exe.addArg("-debug");
    const vmlinux_h = run_exe.addPrefixedOutputFileArg("-o", b.fmt("vmlinux.h", .{}));
    const zigify = b.addTranslateC(.{
        .root_source_file = vmlinux_h,
        .target = target,
        .optimize = optimize,
    });
    zigify.addIncludeDir("src/vmlinux_dumper");
    return b.addModule("vmlinux", .{ .root_source_file = zigify.getOutput() });
}

fn create_btf_sanitizer(b: *std.Build, libbpf: *std.Build.Step.Compile) *std.Build.Step.Compile {
    // build for native
    const target = b.host;
    const optimize: std.builtin.OptimizeMode = .ReleaseFast;

    const exe = b.addExecutable(.{
        .name = "btf_sanitizer",
        .root_source_file = b.path("src/btf_sanitizer/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    const libelf = b.dependency("libelf", .{
        .target = target,
        .optimize = optimize,
    }).artifact("elf");
    exe.linkLibrary(libelf);
    exe.linkLibrary(libbpf);
    exe.linkLibC();
    exe.addIncludePath(b.path("src/btf_sanitizer/"));
    b.installArtifact(exe);

    return exe;
}

fn create_native_tools(b: *std.Build, vmlinux_bin: ?[]const u8) struct { *std.Build.Module, *std.Build.Step.Compile } {
    // build for native
    const target = b.host;
    const optimize: std.builtin.OptimizeMode = .ReleaseFast;

    const libbpf = create_libbpf(b, target, optimize);

    return .{
        create_vmlinux(b, libbpf, vmlinux_bin),
        create_btf_sanitizer(b, libbpf),
    };
}

fn create_bpf(b: *std.Build, vmlinux: *std.Build.Module) *std.Build.Module {
    return b.addModule("bpf", .{
        .root_source_file = b.path("src/bpf/root.zig"),
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
    btf_sanitizer: *std.Build.Step.Compile,
    vmlinux_bin_path: ?[]const u8,
    test_filter: ?[]const u8,
    fuzzing: bool = false,
};

pub fn build(b: *std.Build) !void {
    const target = b.standardTargetOptions(.{});
    // WA for pointer alignment assumption of libbpf
    const optimize: std.builtin.OptimizeMode = .ReleaseFast;

    const build_options = b.addOptions();
    const vmlinux_bin = b.option([]const u8, "vmlinux", "vmlinux binary used for BTF generation");
    debugging = if (b.option(bool, "debug", "enable debugging log")) |v| v else false;
    const kprobes = if (b.option([]const []const u8, "kprobe", "the traced kernel function name")) |v| v else &.{};
    const syscalls = if (b.option([]const []const u8, "syscall", "the traced syscall name")) |v| v else &.{};
    build_options.addOption(@TypeOf(debugging), "debug", debugging);
    build_options.addOption(@TypeOf(kprobes), "kprobes", kprobes);
    build_options.addOption(@TypeOf(syscalls), "syscalls", syscalls);

    const libbpf = create_libbpf(b, target, optimize);
    const vmlinux, const btf_sanitizer = create_native_tools(b, vmlinux_bin);
    const bpf = create_bpf(b, vmlinux);

    const ctx = Ctx{
        .b = b,
        .target = target,
        .optimize = optimize,
        .bpf = bpf,
        .libbpf_step = libbpf,
        .build_options = build_options,
        .vmlinux = vmlinux,
        .btf_sanitizer = btf_sanitizer,
        .vmlinux_bin_path = vmlinux_bin,
        .test_filter = b.option([]const u8, "test", "test filter"),
    };

    // default bpf program
    const bpf_src = if (b.option([]const u8, "bpf", "bpf program source path")) |v| v else "samples/perf_event.zig";
    const exe_src = if (b.option([]const u8, "main", "main executable source path")) |v| v else "src/hello.zig";
    try create_target_step(&ctx, exe_src, bpf_src, null);

    try create_target_step(&ctx, "src/trace.zig", "src/trace.bpf.zig", "trace");

    try create_test_step(&ctx);
    try create_fuzz_test_step(&ctx);

    try create_docs_step(&ctx);
}

fn create_target_step(ctx: *const Ctx, main_path: []const u8, prog_path: []const u8, exe_name: ?[]const u8) !void {
    const prog = create_bpf_prog(ctx, prog_path);

    const exe = ctx.b.addExecutable(.{
        .name = if (exe_name) |name| name else "zbpf",
        .root_source_file = ctx.b.path(main_path),
        .target = ctx.target,
        .optimize = ctx.optimize,
    });
    exe.root_module.addAnonymousImport("@bpf_prog", .{
        .root_source_file = prog,
    });
    exe.root_module.addImport("bpf", ctx.bpf);
    exe.root_module.addOptions("build_options", ctx.build_options);

    exe.linkLibrary(ctx.libbpf_step);
    exe.linkLibC();

    // If it's fuzzing build, -fno-emit-bin
    if (ctx.fuzzing) {
        const build_step = ctx.b.step(if (exe_name) |name| name else "fuzz", "fuzz");
        build_step.dependOn(&exe.step);
    } else {

        // if executable is not named, it is default target
        // otherwise, create a step for it
        if (exe_name) |name| {
            const install_exe = ctx.b.addInstallArtifact(exe, .{});
            const description = ctx.b.fmt("Build {s}", .{name});
            const build_step = ctx.b.step(name, description);
            build_step.dependOn(&install_exe.step);
        } else {
            ctx.b.installArtifact(exe);
        }
    }
}

fn create_test_step(ctx: *const Ctx) !void {
    // Creates a step for unit testing.
    const filter = ctx.test_filter;
    const exe_tests = ctx.b.addTest(.{
        .root_source_file = ctx.b.path("src/tests/root.zig"),
        .target = ctx.target,
        .optimize = ctx.optimize,
        .filter = filter,
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
        if (filter) |f| {
            if (!std.mem.containsAtLeast(u8, entry.name, 1, f)) {
                continue;
            }
        }
        const bpf_prog = create_bpf_prog(ctx, try fs.path.join(ctx.b.allocator, &[_][]const u8{ "samples", entry.name }));
        exe_tests.root_module.addAnonymousImport(try std.fmt.allocPrint(ctx.b.allocator, "@{s}", .{fs.path.stem(entry.name)}), .{
            .root_source_file = bpf_prog,
        });
    }

    // As test runner doesn't support passing arguments,
    // we have to create a temporary file for the debugging flag
    exe_tests.root_module.addAnonymousImport("@build_options", .{
        .root_source_file = ctx.b.addWriteFiles().add(
            "generated_test_build_ctx.zig",
            ctx.b.fmt("pub const debug :bool = {s};", .{if (debugging) "true" else "false"}),
        ),
    });

    const build_test_step = ctx.b.step("test", "Build unit tests");
    build_test_step.dependOn(&install_test.step);
}

fn create_fuzz_test_step(ctx: *const Ctx) !void {
    // Create a dedicated step for building trace with customized vmlinux module
    var _ctx = ctx.*;
    _ctx.vmlinux = ctx.b.addModule("_vmlinux", .{
        .root_source_file = ctx.b.path("src/tests/vmlinux.zig"),
    });
    _ctx.bpf = create_bpf(ctx.b, _ctx.vmlinux);
    _ctx.fuzzing = true;
    try create_target_step(&_ctx, "src/tools/trace/trace.zig", "src/tools/trace/trace.bpf.zig", "_trace", &.{});

    // Creates a step for fuzzing test.
    const exe_tests = ctx.b.addTest(.{
        .root_source_file = ctx.b.path("src/tests/fuzz.zig"),
        .target = ctx.target,
        .optimize = ctx.optimize,
        .filter = ctx.test_filter,
    });
    exe_tests.linkLibrary(ctx.libbpf_step);
    exe_tests.linkLibC();

    // As test runner doesn't support passing arguments,
    // we have to create a temporary file for the debugging flag
    exe_tests.root_module.addAnonymousImport("@build_options", .{
        .root_source_file = ctx.b.addWriteFiles().add(
            "generated_test_build_ctx.zig",
            ctx.b.fmt(
                \\pub const debug :bool = {s};
                \\pub const zig_exe = "{s}";
            , .{
                if (debugging) "true" else "false",
                ctx.b.graph.zig_exe,
            }),
        ),
    });

    const run = ctx.b.addRunArtifact(exe_tests);

    const step = ctx.b.step("fuzz-test", "Build and run fuzzing tests");
    step.dependOn(&run.step);
}

fn create_docs_step(ctx: *const Ctx) !void {
    const exe = ctx.b.addObject(.{
        .name = "docs",
        .root_source_file = ctx.b.path("src/bpf/root.zig"),
        .target = ctx.target,
        .optimize = ctx.optimize,
    });

    const dumb_vmlinux = ctx.b.addModule("dumb_vmlinux", .{ .root_source_file = ctx.b.path("src/docs/dummy_vmlinux.zig") });
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
