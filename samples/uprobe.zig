const std = @import("std");
const bpf = @import("bpf");

var entry = bpf.Map.ArrayMap("entry", u64, 1, 0).init();
var exit = bpf.Map.ArrayMap("exit", u64, 1, 0).init();

const tracked_func = bpf.Uprobe{ .name = "/proc/self/exe", .func = "test_func" };

export fn test_uprobe(args: *tracked_func.Ctx()) linksection(tracked_func.entry_section()) callconv(.c) c_long {
    entry.update(.any, 0, args.arg0());
    return 0;
}

export fn test_uretprobe(args: *tracked_func.Ctx()) linksection(tracked_func.exit_section()) callconv(.c) c_long {
    exit.update(.any, 0, args.ret());
    return 0;
}
