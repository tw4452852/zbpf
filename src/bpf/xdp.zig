/// XDP action which the BPF program returns.
pub const RET = enum(c_int) {
    /// In case of an eBPF program error.
    aborted,
    /// Drop current packet.
    drop,
    /// Pass the packet to the normal network stack for processing.
    pass,
    /// Result in TX bouncing the received packet-page back out the same NIC it arrived on.
    /// This is usually combined with modifying the packet contents before returning action XDP_TX.
    tx,
    /// Redirect to another CPU or forward to another NIC.
    redirect,
};

/// Context for the XDP program.
pub const Meta = extern struct {
    data_begin: u32,
    data_end: u32,
    data_meta: u32,
    ingress_ifindex: u32,
    rx_queue_index: u32,
    egress_ifindex: u32,

    /// Get the pointer to the specified offset in the packet with type casting.
    /// If the offset beyonds the end of the packet, return `null`.
    pub fn get_ptr(self: *Meta, comptime T: type, offset: usize) ?*T {
        const ptr: usize = self.data_begin + offset;

        if (ptr + @sizeOf(T) > self.data_end) return null;

        return @ptrFromInt(ptr);
    }
};
