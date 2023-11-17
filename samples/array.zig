const std = @import("std");
const bpf = @import("bpf");

var array = bpf.Map.ArrayMap("array", u32, 2, 0).init();

export fn test_array() linksection("xdp") c_int {
    const nonexist = array.lookup(2);
    if (nonexist != null) return 1;

    if (array.lookup(0)) |v| {
        if (v.* != 1) return 2;
    } else return 3;

    array.update(.exist, 1, 2);
    return 0;
}
