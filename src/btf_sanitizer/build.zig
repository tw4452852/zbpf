const std = @import("std");

pub fn build(b: *std.Build) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const mod = b.createModule(.{
        .root_source_file = b.path("main.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });

    const exe = b.addExecutable(.{
        .name = "btf_sanitizer",
        .root_module = mod,
    });

    exe.linkLibrary(b.dependency("libelf", .{ .target = target, .optimize = optimize }).artifact("elf"));
    exe.linkLibrary(b.dependency("libbpf", .{ .target = target, .optimize = optimize }).artifact("bpf"));
    exe.addIncludePath(b.path("."));
    b.installArtifact(exe);
}
