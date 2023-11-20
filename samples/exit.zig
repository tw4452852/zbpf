const std = @import("std");
const bpf = @import("bpf");

export fn test_exit() linksection("xdp") c_long {
    bpf.exit(@src(), @as(c_long, 1));
}
