const std = @import("std");

pub fn build(b: *std.build.Builder) void {
    const lib = b.addStaticLibrary(.{
        .name = "z",
        .target = b.standardTargetOptions(.{}),
        .optimize = b.standardOptimizeOption(.{}),
    });
    lib.linkLibC();
    lib.addCSourceFiles(&.{
        "adler32.c",
        "crc32.c",
        "deflate.c",
        "infback.c",
        "inffast.c",
        "inflate.c",
        "inftrees.c",
        "trees.c",
        "zutil.c",
        "compress.c",
        "uncompr.c",
        "gzclose.c",
        "gzlib.c",
        "gzread.c",
        "gzwrite.c",
    }, &.{"-std=c89"});
    lib.installHeader("zconf.h", "zconf.h");
    lib.installHeader("zlib.h", "zlib.h");
    b.installArtifact(lib);
}
