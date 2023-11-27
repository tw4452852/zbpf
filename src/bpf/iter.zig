const std = @import("std");
const helpers = std.os.linux.BPF.kern.helpers;
const vmlinux = @import("vmlinux");

/// A common abstration of different iterator's context
const Meta = extern struct {
    seq: *std.os.linux.BPF.kern.SeqFile,
    session_id: u64,
    seq_num: u64,

    const Self = @This();

    /// Writing into iterator's seq buffer which could be retrieved from userspace.
    pub fn write(self: *Self, data: []const u8) !void {
        const rc = helpers.seq_write(self.seq, @ptrCast(data), @intCast(data.len));
        return switch (rc) {
            0 => {},
            else => error.Unknown,
        };
    }
};

/// Ksym iterator
pub const KSYM = extern struct {
    meta: *Meta,
    ksym: ?*vmlinux.kallsym_iter,
};

/// BPF map iterator
pub const BPF_MAP = extern struct {
    meta: *Meta,
    map: ?*vmlinux.bpf_map,
};
