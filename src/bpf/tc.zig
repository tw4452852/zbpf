pub const SkBuff = extern struct {
    len: u32,
    pkt_type: u32,
    mark: u32,
    queue_mapping: u32,
    protocol: u32,
    vlan_present: u32,
    vlan_tci: u32,
    vlan_proto: u32,
    priority: u32,
    ingress_ifindex: u32,
    ifindex: u32,
    tc_index: u32,
    cb: [5]u32,
    hash: u32,
    tc_classid: u32,
    data: u32,
    data_end: u32,
    napi_id: u32,
    family: u32,
    remote_ip4: u32,
    local_ip4: u32,
    remote_ip6: [4]u32,
    local_ip6: [4]u32,
    remote_port: u32,
    local_port: u32,
    data_meta: u32,
    flow_keys: ?*void,
    tstamp: u64,
    wire_len: u32,
    gso_segs: u32,
    sk: ?*void,
    gso_size: u32,
    tstamp_type: u8,
    hwtstamp: u64,

    /// Get the pointer to the specified offset in the packet with type casting.
    /// If the offset beyonds the end of the packet, return `null`.
    pub fn get_ptr(self: *SkBuff, comptime T: type, offset: usize) ?*T {
        const ptr: usize = self.data + offset;

        if (ptr + @sizeOf(T) > self.data_end) return null;

        return @ptrFromInt(ptr);
    }
};

// TC action which the BPF program returns.
pub const RET = enum(c_int) {
    /// The default action should be taken.
    unspec = -1,
    /// Packet should be proceed.
    ok = 0,
    /// The packet has to re-start classification from the root qdisc.
    reclassify = 1,
    /// The packet should be dropped, no other TC processing should happen.
    shot = 2,
    /// Iterates to the next action, if available.
    pipe = 3,
    /// The packet should be redirected, the details of how and where to are set as side effects by helpers functions.
    redirect = 7,
};
