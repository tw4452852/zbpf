const std = @import("std");
const bpf = @import("bpf");

export fn test_exit() linksection("xdp") c_long {
    bpf.printErr(@src(), @as(c_long, 1));
    return 0;
}
