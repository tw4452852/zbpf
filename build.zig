const std = @import("std");
const builtin = @import("builtin");
const fs = std.fs;

var debugging = false;
var vmlinux_bin_path: ?[]const u8 = null;
var no_install = false;

fn create_bpf_prog(b: *std.Build, optimize: std.builtin.OptimizeMode, endian: std.builtin.Endian, src_path: []const u8, build_options_opt: ?*std.Build.Module) std.Build.LazyPath {
    const host = std.Build.resolveTargetQuery(b, .{});
    const name = fs.path.stem(src_path);

    const prog = b.addObject(.{
        .name = name,
        .root_module = b.createModule(.{
            .root_source_file = b.path(src_path),
            .target = b.resolveTargetQuery(.{
                .cpu_arch = switch (endian) {
                    .big => .bpfeb,
                    .little => .bpfel,
                },
                .os_tag = .freestanding,
            }),
            .optimize = .ReleaseFast, // some assertions in debug mode are blocked by bpf verifier
            .strip = false, // Otherwise BTF sections will be stripped
        }),
    });
    prog.root_module.addImport("bpf", b.modules.get("bpf").?);
    prog.root_module.addImport("vmlinux", b.modules.get("vmlinux").?);
    if (build_options_opt) |build_options| prog.root_module.addImport("@build_options", build_options);

    const run_btf_sanitizer = b.addRunArtifact(b.dependency("btf_sanitizer", .{
        .target = host,
        .optimize = optimize,
    }).artifact("btf_sanitizer"));
    run_btf_sanitizer.addFileArg(prog.getEmittedBin());
    if (vmlinux_bin_path) |vmlinux| {
        run_btf_sanitizer.addPrefixedFileArg("-vmlinux", .{ .cwd_relative = vmlinux });
    }
    if (debugging) run_btf_sanitizer.addArg("-debug");
    return run_btf_sanitizer.addPrefixedOutputFileArg("-o", b.fmt("{s}_sanitized.o", .{name}));
}

fn create_vmlinux(b: *std.Build, optimize: std.builtin.OptimizeMode) *std.Build.Module {
    const host = std.Build.resolveTargetQuery(b, .{});
    const run_exe = b.addRunArtifact(b.dependency("btf_translator", .{
        .target = host,
        .optimize = optimize,
    }).artifact("btf_translator"));

    if (vmlinux_bin_path) |vmlinux| run_exe.addPrefixedFileArg("-vmlinux", .{ .cwd_relative = vmlinux });
    if (debugging) run_exe.addArg("-debug");
    run_exe.addArg("-syscalls");
    const vmlinux_zig = run_exe.addPrefixedOutputFileArg("-o", b.fmt("vmlinux.zig", .{}));

    return b.addModule("vmlinux", .{ .root_source_file = vmlinux_zig });
}

fn create_bpf(b: *std.Build, optimize: std.builtin.OptimizeMode) *std.Build.Module {
    return b.addModule("bpf", .{
        .root_source_file = b.path("src/bpf/root.zig"),
        .imports = &.{.{ .name = "vmlinux", .module = create_vmlinux(b, optimize) }},
    });
}

pub fn build(b: *std.Build) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    vmlinux_bin_path = b.option([]const u8, "vmlinux", "vmlinux binary used for BTF generation");
    if (b.option(bool, "debug", "enable debugging log")) |v| debugging = v;
    if (b.option(bool, "no_install", "alias for -fno-emit-bin, used for testing")) |v| no_install = v;
    const test_filter = b.option([]const u8, "test", "test filter");

    _ = create_bpf(b, optimize);

    create_main_step(b, target, optimize);
    try create_trace_step(b, target, optimize);

    try create_test_step(b, target, optimize, test_filter);
    //try create_fuzz_test_step(b, target, optimize, test_filter);
    try create_docs_step(b, optimize);
}

fn create_main_step(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode) void {
    const bpf_src = if (b.option([]const u8, "bpf", "bpf program source path")) |v| v else "samples/perf_event.zig";
    const exe_src = if (b.option([]const u8, "main", "main executable source path")) |v| v else "src/hello.zig";
    const prog = create_bpf_prog(b, optimize, target.result.cpu.arch.endian(), bpf_src, null);
    _ = create_target_step(b, target, optimize, exe_src, prog, "zbpf");
}

fn create_trace_step(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode) !void {
    const kprobes = if (b.option([]const []const u8, "kprobe", "trace the specified kernel function")) |v| v else &.{};
    const syscalls = if (b.option([]const []const u8, "syscall", "trace the specified syscall")) |v| v else &.{};
    const uprobes = if (b.option([]const []const u8, "uprobe", "trace the specified userspace function")) |v| v else &.{};

    var content = std.ArrayList(u8).init(b.allocator);
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

    const generate_one = struct {
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
    }.generate_one;

    for (kprobes) |l| try generate_one(w, "kprobe", l);
    for (syscalls) |l| try generate_one(w, "syscall", l);
    for (uprobes) |l| try generate_one(w, "uprobe", l);

    try w.writeAll("};");
    const f = b.addWriteFiles().add(
        "generated_tracing.zig",
        try content.toOwnedSlice(),
    );
    const build_options_mod = b.createModule(.{ .root_source_file = f });

    const prog = create_bpf_prog(b, optimize, target.result.cpu.arch.endian(), "src/tools/trace/trace.bpf.zig", build_options_mod);
    const exe = create_target_step(b, target, optimize, "src/tools/trace/trace.zig", prog, "trace");
    exe.root_module.addImport(
        "@build_options",
        build_options_mod,
    );
    exe.linkLibrary(get_libelf(b, target, optimize));
}

fn create_target_step(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode, main_path: []const u8, prog: std.Build.LazyPath, exe_name: []const u8) *std.Build.Step.Compile {
    const options = b.addOptions();
    options.addOptionPath("path", prog);
    const exe = b.addExecutable(.{
        .name = exe_name,
        .root_module = b.createModule(.{
            .root_source_file = b.path(main_path),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        }),
    });
    exe.root_module.addOptions("@bpf_prog", options);
    exe.root_module.addImport("bpf", b.modules.get("bpf").?);
    exe.root_module.addImport("vmlinux", b.modules.get("vmlinux").?);

    exe.linkLibrary(get_libbpf(b, target, optimize));

    const description = b.fmt("Build {s}", .{exe_name});
    const build_step = b.step(exe_name, description);

    if (no_install) {
        // -fno-emit-bin
        build_step.dependOn(&exe.step);
    } else {
        const install_exe = b.addInstallArtifact(exe, .{});
        build_step.dependOn(&install_exe.step);
    }

    return exe;
}

fn create_test_step(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode, test_filter: ?[]const u8) !void {
    // Creates a step for unit testing.
    const exe_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/tests/root.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        }),
        .filters = if (test_filter) |f| &.{f} else &.{},
    });
    exe_tests.linkLibrary(get_libbpf(b, target, optimize));
    exe_tests.root_module.addImport("bpf", b.modules.get("bpf").?);
    exe_tests.setExecCmd(&.{ "sudo", null });

    // Create bpf programs for test
    const build_options = b.addOptions();
    build_options.addOption(bool, "debug", debugging);
    var sample_dir = try fs.cwd().openDir("samples", .{ .iterate = true });
    defer sample_dir.close();
    var it = sample_dir.iterate();
    while (try it.next()) |entry| {
        if (test_filter) |f| {
            if (!std.mem.containsAtLeast(u8, entry.name, 1, f)) {
                continue;
            }
        }
        const prog = create_bpf_prog(b, optimize, target.result.cpu.arch.endian(), try fs.path.join(b.allocator, &.{ "samples", entry.name }), null);
        build_options.addOptionPath(b.fmt("prog_{s}_path", .{fs.path.stem(entry.name)}), prog);
    }
    exe_tests.root_module.addOptions("@build_options", build_options);

    const run_unit_test = b.addRunArtifact(exe_tests);
    const test_bpf_step = b.step("test-bpf", "Build and run bpf package unit tests");
    test_bpf_step.dependOn(&run_unit_test.step);

    // run tools/trace test script
    const run_trace_script = b.addSystemCommand(&.{ "sh", "src/tools/trace/build_check_trace.sh" });
    run_trace_script.setEnvironmentVariable("zig", b.graph.zig_exe);
    run_trace_script.expectExitCode(0);
    run_trace_script.has_side_effects = true;
    const test_tool_trace_step = b.step("test-tool-trace", "Build and run tool/trace unit tests");
    test_tool_trace_step.dependOn(&run_trace_script.step);

    // run btf_translator test
    const run_btf_translator_test = b.dependency("btf_translator", .{
        .target = target,
        .optimize = optimize,
        .@"test" = if (test_filter) |f| f else "",
    }).builder.top_level_steps.get("test").?;
    const test_btf_translator_step = b.step("test-btf-translator", "Build and run btf_translator unit tests");
    test_btf_translator_step.dependOn(&run_btf_translator_test.step);

    // build vmlinux test
    const vmlinux_test = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/tests/vmlinux.zig"),
            .target = target,
            .optimize = optimize,
        }),
        .filters = if (test_filter) |f| &.{f} else &.{},
    });
    vmlinux_test.root_module.addImport("vmlinux", b.modules.get("vmlinux").?);
    const test_vmlinux_step = b.step("test-vmlinux", "Build vmlinux unit test");
    test_vmlinux_step.dependOn(&vmlinux_test.step);

    const vmlinux_offset_test_step = try create_vmlinux_offset_test_step(b, target, optimize, test_filter);

    const test_step = b.step("test", "Build and run all unit tests");
    test_step.dependOn(test_bpf_step);
    test_step.dependOn(test_tool_trace_step);
    test_step.dependOn(test_btf_translator_step);
    test_step.dependOn(test_vmlinux_step);
    test_step.dependOn(vmlinux_offset_test_step);
}

fn create_fuzz_test_step(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode, test_filter: ?[]const u8) !void {
    // Creates a step for fuzzing test.
    const exe_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/tests/fuzz.zig"),
            .target = target,
            .optimize = optimize,
        }),
        .filters = if (test_filter) |f| &.{f} else &.{},
    });
    exe_tests.root_module.addImport("vmlinux", b.modules.get("vmlinux").?);

    const build_options = b.addOptions();
    build_options.addOption(bool, "debug", debugging);
    build_options.addOption([]const u8, "zig_exe", b.graph.zig_exe);
    // As test runner doesn't support passing arguments,
    // we have to create a temporary file for the debugging flag
    exe_tests.root_module.addOptions("@build_options", build_options);

    const run = b.addRunArtifact(exe_tests);

    const step = b.step("fuzz-test", "Build and run fuzzing tests");
    step.dependOn(&run.step);
}

fn create_vmlinux_offset_test_step(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode, test_filter: ?[]const u8) !*std.Build.Step {
    const host = std.Build.resolveTargetQuery(b, .{});
    const generator = b.addExecutable(.{
        .name = "gen_vmlinux_offset_tests",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/tests/gen_vmlinux_offset_tests.zig"),
            .target = host,
            .optimize = optimize,
            .link_libc = true,
        }),
    });
    generator.linkLibrary(get_libbpf(b, host, optimize));
    const run_exe = b.addRunArtifact(generator);

    if (vmlinux_bin_path) |vmlinux| run_exe.addPrefixedFileArg("-vmlinux", .{ .cwd_relative = vmlinux });
    if (debugging) run_exe.addArg("-debug");
    const generated_file = run_exe.addPrefixedOutputFileArg("-o", b.fmt("generated_vmlinux_offset_tests.zig", .{}));

    const exe_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = generated_file,
            .target = target,
            .optimize = optimize,
        }),
        .filters = if (test_filter) |f| &.{f} else &.{},
    });
    exe_tests.root_module.addImport("vmlinux", b.modules.get("vmlinux").?);
    const run = b.addRunArtifact(exe_tests);

    const step = b.step("test-vmlinux-offset", "Build vmlinux offset tests");
    step.dependOn(&run.step);

    return step;
}

fn create_docs_step(b: *std.Build, optimize: std.builtin.OptimizeMode) !void {
    const exe = b.addObject(.{
        .name = "docs",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/bpf/root.zig"),
            .target = b.resolveTargetQuery(.{
                .cpu_arch = .bpfeb,
                .os_tag = .freestanding,
            }),
            .optimize = optimize,
        }),
    });

    exe.root_module.addImport("vmlinux", b.modules.get("vmlinux").?);

    const install_docs = b.addInstallDirectory(.{
        .source_dir = exe.getEmittedDocs(),
        .install_dir = .prefix,
        .install_subdir = "docs",
    });

    const step = b.step("docs", "generate documents");
    step.dependOn(&install_docs.step);
}

fn get_libbpf(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode) *std.Build.Step.Compile {
    return b.dependency("libbpf", .{
        .target = target,
        .optimize = optimize,
    }).artifact("bpf");
}

fn get_libelf(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode) *std.Build.Step.Compile {
    return b.dependency("libelf", .{
        .target = target,
        .optimize = optimize,
    }).artifact("elf");
}
