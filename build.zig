const std = @import("std");
const builtin = @import("builtin");
const fs = std.fs;
const Builder = std.build.Builder;

const debugging = false;

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

fn create_libz(b: *Builder, target: std.zig.CrossTarget, optimize: std.builtin.Mode) *std.build.CompileStep {
    const lib = b.addStaticLibrary(.{
        .name = "z",
        .target = target,
        .optimize = optimize,
    });
    lib.linkLibC();
    lib.addCSourceFiles(&.{
        "external/libz/adler32.c",
        "external/libz/crc32.c",
        "external/libz/deflate.c",
        "external/libz/infback.c",
        "external/libz/inffast.c",
        "external/libz/inflate.c",
        "external/libz/inftrees.c",
        "external/libz/trees.c",
        "external/libz/zutil.c",
        "external/libz/compress.c",
        "external/libz/uncompr.c",
        "external/libz/gzclose.c",
        "external/libz/gzlib.c",
        "external/libz/gzread.c",
        "external/libz/gzwrite.c",
    }, &.{"-std=c89"});

    return lib;
}

fn create_libelf(b: *Builder, target: std.zig.CrossTarget, optimize: std.builtin.Mode) *std.build.CompileStep {
    const lib = b.addStaticLibrary(.{
        .name = "elf",
        .target = target,
        .optimize = optimize,
    });
    lib.linkLibC();
    lib.addCSourceFiles(&.{
        "external/libelf/src/crc32.c",
        "external/libelf/src/elf32_checksum.c",
        "external/libelf/src/elf32_fsize.c",
        "external/libelf/src/elf32_getchdr.c",
        "external/libelf/src/elf32_getehdr.c",
        "external/libelf/src/elf32_getphdr.c",
        "external/libelf/src/elf32_getshdr.c",
        "external/libelf/src/elf32_newehdr.c",
        "external/libelf/src/elf32_newphdr.c",
        "external/libelf/src/elf32_offscn.c",
        "external/libelf/src/elf32_updatefile.c",
        "external/libelf/src/elf32_updatenull.c",
        "external/libelf/src/elf32_xlatetof.c",
        "external/libelf/src/elf32_xlatetom.c",
        "external/libelf/src/elf64_checksum.c",
        "external/libelf/src/elf64_fsize.c",
        "external/libelf/src/elf64_getchdr.c",
        "external/libelf/src/elf64_getehdr.c",
        "external/libelf/src/elf64_getphdr.c",
        "external/libelf/src/elf64_getshdr.c",
        "external/libelf/src/elf64_newehdr.c",
        "external/libelf/src/elf64_newphdr.c",
        "external/libelf/src/elf64_offscn.c",
        "external/libelf/src/elf64_updatefile.c",
        "external/libelf/src/elf64_updatenull.c",
        "external/libelf/src/elf64_xlatetof.c",
        "external/libelf/src/elf64_xlatetom.c",
        "external/libelf/src/elf_begin.c",
        "external/libelf/src/elf_clone.c",
        "external/libelf/src/elf_cntl.c",
        "external/libelf/src/elf_compress.c",
        "external/libelf/src/elf_compress_gnu.c",
        "external/libelf/src/elf_end.c",
        "external/libelf/src/elf_error.c",
        "external/libelf/src/elf_fill.c",
        "external/libelf/src/elf_flagdata.c",
        "external/libelf/src/elf_flagehdr.c",
        "external/libelf/src/elf_flagelf.c",
        "external/libelf/src/elf_flagphdr.c",
        "external/libelf/src/elf_flagscn.c",
        "external/libelf/src/elf_flagshdr.c",
        "external/libelf/src/elf_getarhdr.c",
        "external/libelf/src/elf_getaroff.c",
        "external/libelf/src/elf_getarsym.c",
        "external/libelf/src/elf_getbase.c",
        "external/libelf/src/elf_getdata.c",
        "external/libelf/src/elf_getdata_rawchunk.c",
        "external/libelf/src/elf_getident.c",
        "external/libelf/src/elf_getphdrnum.c",
        "external/libelf/src/elf_getscn.c",
        "external/libelf/src/elf_getshdrnum.c",
        "external/libelf/src/elf_getshdrstrndx.c",
        "external/libelf/src/elf_gnu_hash.c",
        "external/libelf/src/elf_hash.c",
        "external/libelf/src/elf_kind.c",
        "external/libelf/src/elf_memory.c",
        "external/libelf/src/elf_ndxscn.c",
        "external/libelf/src/elf_newdata.c",
        "external/libelf/src/elf_newscn.c",
        "external/libelf/src/elf_next.c",
        "external/libelf/src/elf_nextscn.c",
        "external/libelf/src/elf_rand.c",
        "external/libelf/src/elf_rawdata.c",
        "external/libelf/src/elf_rawfile.c",
        "external/libelf/src/elf_readall.c",
        "external/libelf/src/elf_scnshndx.c",
        "external/libelf/src/elf_strptr.c",
        "external/libelf/src/elf_update.c",
        "external/libelf/src/elf_version.c",
        "external/libelf/src/gelf_checksum.c",
        "external/libelf/src/gelf_fsize.c",
        "external/libelf/src/gelf_getauxv.c",
        "external/libelf/src/gelf_getchdr.c",
        "external/libelf/src/gelf_getclass.c",
        "external/libelf/src/gelf_getdyn.c",
        "external/libelf/src/gelf_getehdr.c",
        "external/libelf/src/gelf_getlib.c",
        "external/libelf/src/gelf_getmove.c",
        "external/libelf/src/gelf_getnote.c",
        "external/libelf/src/gelf_getphdr.c",
        "external/libelf/src/gelf_getrel.c",
        "external/libelf/src/gelf_getrela.c",
        "external/libelf/src/gelf_getshdr.c",
        "external/libelf/src/gelf_getsym.c",
        "external/libelf/src/gelf_getsyminfo.c",
        "external/libelf/src/gelf_getsymshndx.c",
        "external/libelf/src/gelf_getverdaux.c",
        "external/libelf/src/gelf_getverdef.c",
        "external/libelf/src/gelf_getvernaux.c",
        "external/libelf/src/gelf_getverneed.c",
        "external/libelf/src/gelf_getversym.c",
        "external/libelf/src/gelf_newehdr.c",
        "external/libelf/src/gelf_newphdr.c",
        "external/libelf/src/gelf_offscn.c",
        "external/libelf/src/gelf_update_auxv.c",
        "external/libelf/src/gelf_update_dyn.c",
        "external/libelf/src/gelf_update_ehdr.c",
        "external/libelf/src/gelf_update_lib.c",
        "external/libelf/src/gelf_update_move.c",
        "external/libelf/src/gelf_update_phdr.c",
        "external/libelf/src/gelf_update_rel.c",
        "external/libelf/src/gelf_update_rela.c",
        "external/libelf/src/gelf_update_shdr.c",
        "external/libelf/src/gelf_update_sym.c",
        "external/libelf/src/gelf_update_syminfo.c",
        "external/libelf/src/gelf_update_symshndx.c",
        "external/libelf/src/gelf_update_verdaux.c",
        "external/libelf/src/gelf_update_verdef.c",
        "external/libelf/src/gelf_update_vernaux.c",
        "external/libelf/src/gelf_update_verneed.c",
        "external/libelf/src/gelf_update_versym.c",
        "external/libelf/src/gelf_xlate.c",
        "external/libelf/src/gelf_xlatetof.c",
        "external/libelf/src/gelf_xlatetom.c",
        "external/libelf/src/libelf_crc32.c",
        "external/libelf/src/libelf_next_prime.c",
        "external/libelf/src/next_prime.c",
        "external/libelf/src/nlist.c",
    }, &.{"-DHAVE_CONFIG_H"});

    lib.addIncludePath("external/libelf/include");
    lib.addIncludePath("external/libelf/src");
    lib.addIncludePath("external/libz");

    return lib;
}

fn create_libbpf(b: *Builder, target: std.zig.CrossTarget, optimize: std.builtin.Mode) *std.build.CompileStep {
    const libz = create_libz(b, target, optimize);
    const libelf = create_libelf(b, target, optimize);

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
        "-DZIG_BTF_WA",
    };
    libbpf.addCSourceFiles(&libbpfSources, &libbpfFlags);
    libbpf.addIncludePath("external/libbpf/include");
    libbpf.addIncludePath("external/libbpf/include/uapi");
    libbpf.addIncludePath("external/libelf/include");
    libbpf.addIncludePath("external/libz");
    libbpf.linkLibC();
    libbpf.linkLibrary(libz);
    libbpf.linkLibrary(libelf);

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

fn create_vmlinux(b: *Builder) *Builder.Module {
    const target = std.zig.CrossTarget.fromTarget(builtin.target);
    const optimize: std.builtin.Mode = .ReleaseFast;

    const libbpf = create_libbpf(b, target, optimize);
    const exe = b.addExecutable(.{
        .name = "vmlinux_dumper",
        .root_source_file = .{ .path = "src/vmlinux_dumper/main.zig" },
        .target = target,
        .optimize = optimize,
    });
    exe.linkLibrary(libbpf);
    exe.linkLibC();
    exe.addIncludePath("external/libbpf/src");
    b.installArtifact(exe);

    const run_exe = b.addRunArtifact(exe);
    const vmlinux_bin = b.option([]const u8, "vmlinux", "vmlinux binary used for BTF generation");
    if (vmlinux_bin) |vmlinux| run_exe.addArg(vmlinux);
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

fn create_bpf(b: *Builder) *Builder.Module {
    return b.addModule("bpf", .{
        .source_file = .{ .path = "src/bpf/root.zig" },
        .dependencies = &.{.{ .name = "vmlinux", .module = create_vmlinux(b) }},
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
    const libbpf = create_libbpf(b, target, optimize);

    // build bpf package
    const bpf = create_bpf(b);

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

    // add debug option to test
    const tests_options = b.addOptions();
    exe_tests.addOptions("build_options", tests_options);
    tests_options.addOption(bool, "debug", debugging);

    const run_test_step = b.step("test", "Build unit tests");
    run_test_step.dependOn(&install_test.step);
}
