const std = @import("std");
pub const allocator = std.testing.allocator;
pub const libbpf = @cImport({
    @cInclude("libbpf.h");
    @cInclude("bpf.h");
});
const build_options = @import("build_options");

pub fn dbg_printf(level: libbpf.libbpf_print_level, fmt: [*c]const u8, args: [*c]libbpf.__va_list_tag) callconv(.C) c_int {
    if (!build_options.debug and level == libbpf.LIBBPF_DEBUG) return 0;

    return libbpf.vdprintf(std.io.getStdErr().handle, fmt, args);
}

test {
    _ = @import("array.zig");
    _ = @import("hash.zig");
    _ = @import("perf_event.zig");
    _ = @import("tracepoint.zig");
    _ = @import("ringbuf.zig");
    _ = @import("iterator.zig");
    _ = @import("fentry.zig");
}
