const std = @import("std");
pub const allocator = std.testing.allocator;
pub const libbpf = @cImport({
    @cInclude("libbpf.h");
    @cInclude("bpf.h");
    @cInclude("btf.h");
});
const build_options = @import("build_options");

pub fn dbg_printf(level: libbpf.libbpf_print_level, fmt: [*c]const u8, args: @typeInfo(@typeInfo(@typeInfo(libbpf.libbpf_print_fn_t).Optional.child).Pointer.child).Fn.params[2].type.?) callconv(.C) c_int {
    if (!build_options.debug and level == libbpf.LIBBPF_DEBUG) return 0;

    return libbpf.vdprintf(std.io.getStdErr().handle, fmt, args);
}

pub fn btf_name_exist(name: []const u8) bool {
    if (libbpf.btf__load_vmlinux_btf()) |btf| {
        const i = libbpf.btf__find_by_name(btf, name.ptr);
        return if (i > 0) true else false;
    }
    return false;
}

const tracefs_mount_dir = "./tracefs";

pub fn open_tracebuf_pipe(clean: bool) !std.fs.File {
    const cwd = std.fs.cwd();
    try cwd.makeDir(tracefs_mount_dir);
    const ret = std.posix.errno(std.os.linux.mount("zbpf_test", tracefs_mount_dir, "tracefs", 0, 0));
    if (ret != .SUCCESS) return error.MOUNT;

    // clean trace buffer if request
    if (clean) {
        try cwd.writeFile2(.{
            .sub_path = tracefs_mount_dir ++ "/trace",
            .data = "\n",
            .flags = .{},
        });
    }

    return try cwd.openFile(tracefs_mount_dir ++ "/trace_pipe", .{});
}

pub fn close_tracebuf_pipe(f: std.fs.File) void {
    f.close();
    const ret = std.posix.errno(std.os.linux.umount(tracefs_mount_dir));
    if (ret != .SUCCESS) @panic(@tagName(ret));
    std.fs.cwd().deleteDir(tracefs_mount_dir) catch unreachable;
}

test {
    _ = @import("exit.zig");
    _ = @import("panic.zig");
    _ = @import("trace_printk.zig");
    _ = @import("array.zig");
    _ = @import("hash.zig");
    _ = @import("perf_event.zig");
    _ = @import("tracepoint.zig");
    _ = @import("ringbuf.zig");
    _ = @import("iterator.zig");
    _ = @import("fentry.zig");
    _ = @import("kprobe.zig");
    _ = @import("kmulprobe.zig");
    _ = @import("ksyscall.zig");
    _ = @import("xdp_ping.zig");
}
