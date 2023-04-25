const std = @import("std");
const builtin = @import("builtin");
const fs = std.fs;
const Builder = std.build.Builder;

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
    prog.step.dependOn(ctx.mounting_step);

    return prog;
}

fn create_libbpf(b: *Builder, target: std.zig.CrossTarget, optimize: std.builtin.Mode) *std.build.CompileStep {
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

const Ctx = struct {
    b: *Builder,
    target: std.zig.CrossTarget,
    optimize: std.builtin.Mode,
    bpf: *Builder.Module,
    mounting_step: *Builder.Step,
    libbpf_step: *std.build.CompileStep,
};

pub fn build(b: *Builder) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // mount tracefs for structure generation
    const mounting_step = create_mounting_tracefs_step(b);

    // build libbpf
    const libbpf = create_libbpf(b, target, optimize);

    // build bpf package
    const bpf = b.addModule("bpf", .{
        .source_file = .{ .path = "src/bpf/root.zig" },
    });

    const ctx = Ctx{
        .b = b,
        .target = target,
        .optimize = optimize,
        .bpf = bpf,
        .mounting_step = mounting_step,
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

    exe.linkLibrary(libbpf);
    exe.linkLibC();
    exe.addIncludePath("external/libbpf/src");
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

    const run_test = b.addRunArtifact(exe_tests);
    const run_test_step = b.step("test", "Run unit tests");
    run_test_step.dependOn(&run_test.step);
}
