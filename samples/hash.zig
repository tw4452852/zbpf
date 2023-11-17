const std = @import("std");
const bpf = @import("bpf");

var hash = bpf.Map.HashMap("hash", u32, u32, 2, 0).init();

export fn test_hash() linksection("xdp") c_int {
    const nonexist = hash.lookup(2);
    if (nonexist != null) return 1;

    if (hash.lookup(0)) |v| {
        if (v.* != 1) return 2;
    } else return 3;

    hash.delete(0);
    hash.update(.noexist, 1, 2);
    return 0;
}
