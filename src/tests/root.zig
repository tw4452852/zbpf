const std = @import("std");
pub const allocator = std.testing.allocator;
pub const libbpf = @cImport({
    @cInclude("libbpf.h");
    @cInclude("bpf.h");
});

pub fn dbg_printf(_: libbpf.libbpf_print_level, fmt: [*c]const u8, args: [*c]libbpf.__va_list_tag) callconv(.C) c_int {
    return libbpf.vdprintf(std.io.getStdErr().handle, fmt, args);
}

test {
    _ = @import("array.zig");
    _ = @import("hash.zig");
    _ = @import("perf_event.zig");
    _ = @import("tracepoint.zig");
    _ = @import("ringbuf.zig");
}
