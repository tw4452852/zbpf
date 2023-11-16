pub const RET = enum(c_int) {
    aborted,
    drop,
    pass,
    tx,
    redirect,
};

pub const Meta = extern struct {
    data_begin: u32,
    data_end: u32,
    data_meta: u32,
    ingress_ifindex: u32,
    rx_queue_index: u32,
    egress_ifindex: u32,

    pub fn get_ptr(self: *Meta, comptime T: type, offset: u32) ?*T {
        const ptr: usize = self.data_begin + offset;

        if (ptr + @sizeOf(T) > self.data_end) return null;

        return @ptrFromInt(ptr);
    }
};
