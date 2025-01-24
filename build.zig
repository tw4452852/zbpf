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
    prog.root_module.addAnonymousImport("@build_options", .{
        .root_source_file = ctx.build_options,
    });

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
        .optimize = if (optimize != .ReleaseFast) .ReleaseFast else optimize, // WA for pointer alignment assumption of libbpf
    }).artifact("bpf");
}

fn create_libelf(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode) *std.Build.Step.Compile {
    return b.dependency("libelf", .{
        .target = target,
        .optimize = if (optimize != .ReleaseFast) .ReleaseFast else optimize, // WA for pointer alignment assumption of libelf
    }).artifact("elf");
}

fn create_vmlinux(b: *std.Build, libbpf: *std.Build.Step.Compile, vmlinux_bin: ?[]const u8) *std.Build.Module {
    const exe = create_btf_translator(b, libbpf);
    const run_exe = b.addRunArtifact(exe);

    if (vmlinux_bin) |vmlinux| run_exe.addPrefixedFileArg("-vmlinux", .{ .cwd_relative = vmlinux });
    if (debugging) run_exe.addArg("-debug");
    run_exe.addArg("-syscalls");
    const vmlinux_zig = run_exe.addPrefixedOutputFileArg("-o", b.fmt("vmlinux.zig", .{}));

    return b.addModule("vmlinux", .{ .root_source_file = vmlinux_zig });
}

fn create_btf_translator(b: *std.Build, libbpf: *std.Build.Step.Compile) *std.Build.Step.Compile {
    // build for native
    const target = b.graph.host;
    const optimize: std.builtin.OptimizeMode = .ReleaseFast;

    const exe = b.addExecutable(.{
        .name = "btf_translator",
        .root_source_file = b.path("src/btf_translator/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    exe.linkLibrary(libbpf);
    exe.linkLibC();
    b.installArtifact(exe);

    return exe;
}

fn create_btf_sanitizer(b: *std.Build, libbpf: *std.Build.Step.Compile, libelf: *std.Build.Step.Compile) *std.Build.Step.Compile {
    // build for native
    const target = b.graph.host;
    const optimize: std.builtin.OptimizeMode = .ReleaseFast;

    const exe = b.addExecutable(.{
        .name = "btf_sanitizer",
        .root_source_file = b.path("src/btf_sanitizer/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    exe.linkLibrary(libelf);
    exe.linkLibrary(libbpf);
    exe.linkLibC();
    exe.addIncludePath(b.path("src/btf_sanitizer/"));
    b.installArtifact(exe);

    return exe;
}

fn create_native_tools(b: *std.Build, vmlinux_bin: ?[]const u8, optimize: std.builtin.OptimizeMode) struct { *std.Build.Module, *std.Build.Step.Compile } {
    // build for native
    const target = b.graph.host;

    const libbpf = create_libbpf(b, target, optimize);
    const libelf = create_libelf(b, target, optimize);

    return .{
        create_vmlinux(b, libbpf, vmlinux_bin),
        create_btf_sanitizer(b, libbpf, libelf),
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
    build_options: std.Build.LazyPath,
    btf_sanitizer: *std.Build.Step.Compile,
    vmlinux_bin_path: ?[]const u8,
    test_filter: ?[]const u8,
    install: bool,
};

pub fn build(b: *std.Build) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const build_options = b.addOptions();
    const vmlinux_bin = b.option([]const u8, "vmlinux", "vmlinux binary used for BTF generation");
    debugging = if (b.option(bool, "debug", "enable debugging log")) |v| v else false;
    const install = if (b.option(bool, "install", "alias for -fno-emit-bin, used for testing")) |v| v else true;

    const libbpf = create_libbpf(b, target, optimize);
    const vmlinux, const btf_sanitizer = create_native_tools(b, vmlinux_bin, optimize);
    const bpf = create_bpf(b, vmlinux);

    const ctx = Ctx{
        .b = b,
        .target = target,
        .optimize = optimize,
        .bpf = bpf,
        .libbpf_step = libbpf,
        .build_options = build_options.getOutput(),
        .vmlinux = vmlinux,
        .btf_sanitizer = btf_sanitizer,
        .vmlinux_bin_path = vmlinux_bin,
        .test_filter = b.option([]const u8, "test", "test filter"),
        .install = install,
    };

    try create_main_step(&ctx);
    try create_trace_step(&ctx);
    try create_test_step(&ctx);
    try create_fuzz_test_step(&ctx);
    try create_docs_step(&ctx);
}

fn create_main_step(ctx: *const Ctx) !void {
    const bpf_src = if (ctx.b.option([]const u8, "bpf", "bpf program source path")) |v| v else "samples/perf_event.zig";
    const exe_src = if (ctx.b.option([]const u8, "main", "main executable source path")) |v| v else "src/hello.zig";
    try create_target_step(ctx, exe_src, bpf_src, "zbpf", null);
}

fn create_trace_step(ctx: *const Ctx) !void {
    const kprobes = if (ctx.b.option([]const []const u8, "kprobe", "trace the specified kernel function")) |v| v else &.{};
    const syscalls = if (ctx.b.option([]const []const u8, "syscall", "trace the specified syscall")) |v| v else &.{};
    const uprobes = if (ctx.b.option([]const []const u8, "uprobe", "trace the specified userspace function")) |v| v else &.{};

    var content = std.ArrayList(u8).init(ctx.b.allocator);
    defer content.deinit();
    const w = content.writer();
    try w.writeAll(
        \\pub const Kind = enum { kprobe, syscall, uprobe };
        \\pub const TraceFunc = struct {
        \\  kind: Kind,
        \\  name: []const u8,
        \\  args: []const []const u8,
        \\  with_stack: bool,
        \\  with_lbr: bool,
        \\};
        \\pub const tracing_funcs = [_]TraceFunc{
        \\
    );

    const Closure = struct {
        fn generate_one(writer: std.ArrayList(u8).Writer, kind: []const u8, l: []const u8) !void {
            const colon = std.mem.indexOfScalar(u8, l, ':');
            const name = if (colon) |ci| l[0..ci] else l;
            try writer.print(".{{ .kind = .{s}, .name = \"{s}\", ", .{ kind, name });

            var with_stack = false;
            var with_lbr = false;
            if (colon) |ci| {
                var it = std.mem.tokenizeScalar(u8, l[ci + 1 ..], ',');
                try writer.writeAll(".args = &.{");
                while (it.next()) |arg| {
                    if (std.mem.eql(u8, arg, "stack")) {
                        with_stack = true;
                    } else if (std.mem.eql(u8, arg, "lbr")) {
                        with_lbr = true;
                    } else {
                        try writer.print("\"{s}\", ", .{arg});
                    }
                }
                try writer.writeAll("}, ");
            } else {
                try writer.writeAll(".args = &.{}, ");
            }

            try writer.print(".with_lbr = {}, ", .{with_lbr});
            try writer.print(".with_stack = {}, }},\n", .{with_stack});
        }
    };

    for (kprobes) |l| try Closure.generate_one(w, "kprobe", l);
    for (syscalls) |l| try Closure.generate_one(w, "syscall", l);
    for (uprobes) |l| try Closure.generate_one(w, "uprobe", l);

    try w.writeAll("};");
    const f = ctx.b.addWriteFiles().add(
        "generated_tracing_ctx.zig",
        try content.toOwnedSlice(),
    );

    // Create a new ctx with tracing functions
    var ctx_with_tracing: Ctx = ctx.*;
    ctx_with_tracing.build_options = f;

    try create_target_step(&ctx_with_tracing, "src/tools/trace/trace.zig", "src/tools/trace/trace.bpf.zig", "trace", &.{create_libelf(ctx.b, ctx.target, ctx.optimize)});
}

fn create_target_step(ctx: *const Ctx, main_path: []const u8, prog_path: []const u8, exe_name: []const u8, extra_libs_opt: ?[]const *std.Build.Step.Compile) !void {
    const prog = create_bpf_prog(ctx, prog_path);

    const exe = ctx.b.addExecutable(.{
        .name = exe_name,
        .root_source_file = ctx.b.path(main_path),
        .target = ctx.target,
        .optimize = ctx.optimize,
    });
    exe.root_module.addAnonymousImport("@bpf_prog", .{
        .root_source_file = prog,
    });
    exe.root_module.addImport("bpf", ctx.bpf);
    exe.root_module.addImport("vmlinux", ctx.vmlinux);
    exe.root_module.addAnonymousImport("@build_options", .{
        .root_source_file = ctx.build_options,
    });

    exe.linkLibrary(ctx.libbpf_step);
    exe.linkLibC();
    if (extra_libs_opt) |extra_libs| for (extra_libs) |lib| {
        exe.linkLibrary(lib);
    };

    const description = ctx.b.fmt("Build {s}", .{exe_name});
    const build_step = ctx.b.step(exe_name, description);

    if (!ctx.install) {
        // -fno-emit-bin
        build_step.dependOn(&exe.step);
    } else {
        const install_exe = ctx.b.addInstallArtifact(exe, .{});
        build_step.dependOn(&install_exe.step);
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
    exe_tests.setExecCmd(&.{ "sudo", null });

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

    const run_unit_test = ctx.b.addRunArtifact(exe_tests);
    const test_bpf_step = ctx.b.step("test-bpf", "Build and run bpf package unit tests");
    test_bpf_step.dependOn(&run_unit_test.step);

    // run tools/trace test script
    const run_trace_script = ctx.b.addSystemCommand(&.{ "sh", "src/tools/trace/build_check_trace.sh" });
    run_trace_script.expectExitCode(0);
    run_trace_script.has_side_effects = true;
    const test_tool_trace_step = ctx.b.step("test-tool-trace", "Build and run tool/trace unit tests");
    test_tool_trace_step.dependOn(&run_trace_script.step);

    // run btf_translator test
    const btf_translator_test = create_btf_translator_test(ctx);
    const run_btf_translator_test = ctx.b.addRunArtifact(btf_translator_test);
    const test_btf_translator_step = ctx.b.step("test-btf-translator", "Build and run btf_translator unit tests");
    test_btf_translator_step.dependOn(&run_btf_translator_test.step);

    // build vmlinux test
    const vmlinux_test = ctx.b.addTest(.{
        .root_source_file = ctx.b.path("src/tests/vmlinux.zig"),
        .target = ctx.target,
        .optimize = ctx.optimize,
    });
    vmlinux_test.root_module.addAnonymousImport("@build_options", .{
        .root_source_file = ctx.b.addWriteFiles().add(
            "generated_test_build_ctx.zig",
            ctx.b.fmt("pub const vmlinux_bin_path :[:0]const u8 = \"{s}\";", .{if (ctx.vmlinux_bin_path) |path| path else ""}),
        ),
    });
    vmlinux_test.root_module.addImport("vmlinux", ctx.vmlinux);
    vmlinux_test.linkLibrary(ctx.libbpf_step);
    const test_vmlinux_step = ctx.b.step("test-vmlinux", "Build vmlinux unit test");
    test_vmlinux_step.dependOn(&vmlinux_test.step);

    const test_step = ctx.b.step("test", "Build and run all unit tests");
    test_step.dependOn(test_bpf_step);
    test_step.dependOn(test_tool_trace_step);
    test_step.dependOn(test_btf_translator_step);
    test_step.dependOn(test_vmlinux_step);
}

fn create_btf_translator_test(ctx: *const Ctx) *std.Build.Step.Compile {
    const exe = ctx.b.addTest(.{
        .root_source_file = ctx.b.path("src/btf_translator/main.zig"),
        .target = ctx.target,
        .optimize = ctx.optimize,
        .filter = ctx.test_filter,
    });

    exe.linkLibrary(ctx.libbpf_step);
    exe.linkLibC();

    return exe;
}

fn create_fuzz_test_step(ctx: *const Ctx) !void {
    // Creates a step for fuzzing test.
    const exe_tests = ctx.b.addTest(.{
        .root_source_file = ctx.b.path("src/tests/fuzz.zig"),
        .target = ctx.target,
        .optimize = ctx.optimize,
        .filter = ctx.test_filter,
    });
    exe_tests.root_module.addImport("vmlinux", ctx.vmlinux);

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

    exe.root_module.addImport("vmlinux", ctx.vmlinux);

    const install_docs = ctx.b.addInstallDirectory(.{
        .source_dir = exe.getEmittedDocs(),
        .install_dir = .prefix,
        .install_subdir = "docs",
    });

    const step = ctx.b.step("docs", "generate documents");
    step.dependOn(&install_docs.step);
}
