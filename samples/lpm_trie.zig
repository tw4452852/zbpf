const std = @import("std");
const bpf = @import("bpf");
const exit = bpf.exit;

const Ipv4LpmKey = extern struct {
    prefixlen: u32,
    data: u32,
};

var src_map = bpf.Map.LpmTrie("src_map", Ipv4LpmKey, u64, 64, 1).init();

export fn test_lpm_trie() linksection("xdp") c_int {
    var src_key = Ipv4LpmKey{
        .prefixlen = 32,
        .data = 33554559, // 127.0.0.2
    };

    const nonexist = src_map.lookup(src_key);
    if (nonexist != null) exit(@src(), @as(c_long, 1));

    src_key.data = 16777343; // 127.0.0.1

    if (src_map.lookup(src_key)) |v| {
        if (v.* != 1) exit(@src(), @as(c_long, 1));
    } else exit(@src(), @as(c_long, 1));

    src_map.delete(src_key);

    src_key.data = 50331775; // 127.0.0.3
    src_map.update(.noexist, src_key, 2);
    return 0;
}
