const std = @import("std");
const builtin = @import("builtin");
const fs = std.fs;

const debugging = true;

fn create_bpf_prog(b: *std.build.Builder, target: std.zig.CrossTarget, src_path: ?[]const u8) *std.build.CompileStep {
    const name = fs.path.stem(src_path orelse "?");

    const pkg = b.addModule("bpf", .{
        .source_file = .{ .path = "src/bpf/root.zig" },
    });

    const prog = b.addObject(.{
        .name = name,
        .root_source_file = if (src_path) |path| .{
            .path = path,
        } else null,
        .target = .{
            .cpu_arch = switch ((target.cpu_arch orelse builtin.cpu.arch).endian()) {
                .Big => .bpfeb,
                .Little => .bpfel,
            },
            .os_tag = .freestanding,
        },
        .optimize = .ReleaseFast,
    });
    prog.addModule("bpf", pkg);
    prog.linkLibC();

    if (debugging) {
        prog.emit_llvm_ir = .{
            .emit_to = std.fmt.allocPrint(b.allocator, "/tmp/{s}.ir", .{name}) catch unreachable,
        };
    }

    return prog;
}

fn create_libbpf(b: *std.build.Builder, target: std.zig.CrossTarget, optimize: std.builtin.Mode) *std.build.CompileStep {
    const libbpf = b.addStaticLibrary(.{
        .name = "libbpf",
        .target = target,
        .optimize = optimize,
    });
    const libbpfSources = [_][]const u8{
        "external/libbpf/src/bpf.c",
        "external/libbpf/src/btf.c",
        "external/libbpf/src/libbpf.c",
        "external/libbpf/src/libbpf_errno.c",
        "external/libbpf/src/netlink.c",
        "external/libbpf/src/nlattr.c",
        "external/libbpf/src/str_error.c",
        "external/libbpf/src/libbpf_probes.c",
        "external/libbpf/src/bpf_prog_linfo.c",
        "external/libbpf/src/btf_dump.c",
        "external/libbpf/src/hashmap.c",
        "external/libbpf/src/ringbuf.c",
        "external/libbpf/src/strset.c",
        "external/libbpf/src/linker.c",
        "external/libbpf/src/gen_loader.c",
        "external/libbpf/src/relo_core.c",
        "external/libbpf/src/usdt.c",
    };
    const libbpfFlags = [_][]const u8{
        "-D_LARGEFILE64_SOURCE",
        "-D_FILE_OFFSET_BITS=64",
    };
    libbpf.addCSourceFiles(&libbpfSources, &libbpfFlags);
    libbpf.addIncludePath("external/libbpf/include");
    libbpf.addIncludePath("external/libbpf/include/uapi");
    libbpf.linkLibC();
    libbpf.linkSystemLibrary("elf");
    libbpf.linkSystemLibrary("z");

    return libbpf;
}

pub fn build(b: *std.build.Builder) !void {
    // Standard target options allows the person running `zig build` to choose
    // what target to build for. Here we do not override the defaults, which
    // means any target is allowed, and the default is native. Other options
    // for restricting supported target set are available.
    const target = b.standardTargetOptions(.{});

    // Standard release options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall.
    const optimize = b.standardOptimizeOption(.{});

    // build bpf program
    const bpf_src = b.option([]const u8, "bpf", "bpf program source path");
    const prog = create_bpf_prog(b, target, bpf_src);

    // build libbpf
    const libbpf = create_libbpf(b, target, optimize);

    // mount tracefs for structure generation
    fs.cwd().makeDir("src/bpf/tracefs") catch {};
    _ = std.os.linux.getErrno(std.os.linux.mount("zbpf", "src/bpf/tracefs", "tracefs", 0, 0));

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

    exe.linkLibrary(libbpf);
    exe.linkLibC();
    exe.addIncludePath("external/libbpf/src");

    b.installArtifact(exe);

    // This *creates* a RunStep in the build graph, to be executed when another
    // step is evaluated that depends on it. The next line below will establish
    // such a dependency.
    const run_cmd = b.addRunArtifact(exe);

    // By making the run step depend on the install step, it will be run from the
    // installation directory rather than directly from within the cache directory.
    // This is not necessary, however, if the application depends on other installed
    // files, this ensures they will be present and in the expected location.
    run_cmd.step.dependOn(b.getInstallStep());

    // This allows the user to pass arguments to the application in the build
    // command itself, like this: `zig build run -- arg1 arg2 etc`
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    // This creates a build step. It will be visible in the `zig build --help` menu,
    // and can be selected like this: `zig build run`
    // This will evaluate the `run` step rather than the default, which is "install".
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

    // Create bpf programs for test
    var sample_dir = try fs.cwd().openIterableDir("samples", .{});
    defer sample_dir.close();
    var it = sample_dir.iterate();
    while (try it.next()) |entry| {
        const bpf_prog = create_bpf_prog(b, target, try fs.path.join(b.allocator, &[_][]const u8{ "samples", entry.name }));
        exe_tests.addAnonymousModule(try std.fmt.allocPrint(b.allocator, "@{s}", .{fs.path.stem(entry.name)}), .{
            .source_file = bpf_prog.getOutputSource(),
        });
    }

    // Similar to creating the run step earlier, this exposes a `test` step to
    // the `zig build --help` menu, providing a way for the user to request
    // running the unit tests.
    const run_test = b.addRunArtifact(exe_tests);

    const run_test_step = b.step("test", "Run unit tests");
    run_test_step.dependOn(&run_test.step);
}
