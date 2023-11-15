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

    pub fn data(self: *Meta) []u8 {
        return @as([*c]u8, @ptrFromInt(self.data_begin))[0 .. self.data_end - self.data_begin];
    }
};
