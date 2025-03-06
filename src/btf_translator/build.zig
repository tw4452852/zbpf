const std = @import("std");

pub fn build(b: *std.Build) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const libbpf = b.dependency("libbpf", .{ .target = target, .optimize = optimize }).artifact("bpf");

    const mod = b.createModule(.{
        .root_source_file = b.path("main.zig"),
        .target = target,
        .optimize = optimize,
    });

    const exe = b.addExecutable(.{
        .name = "btf_translator",
        .root_module = mod,
    });
    exe.linkLibrary(libbpf);
    exe.linkLibC();
    b.installArtifact(exe);

    const test_filter = b.option([]const u8, "test", "test filter");
    const test_exe = b.addTest(.{
        .root_module = mod,
        .filters = if (test_filter) |f| &.{f} else &.{},
    });
    test_exe.linkLibrary(libbpf);
    test_exe.linkLibC();
    const run_test = b.addRunArtifact(test_exe);
    const test_step = b.step("test", "Build and run unit tests");
    test_step.dependOn(&run_test.step);
}
