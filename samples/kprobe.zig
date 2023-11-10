const std = @import("std");
const bpf = @import("bpf");

var entry = bpf.Map.ArrayMap("entry", u64, 1, 0).init();
var exit = bpf.Map.ArrayMap("exit", i64, 1, 0).init();

const tracked_func = bpf.Kprobe{ .name = "path_listxattr" };

export fn test_kprobe(args: *tracked_func.Ctx()) linksection(tracked_func.entry_section()) callconv(.C) c_long {
    const arg0 = args.arg0() catch return 1;
    const arg1 = args.arg1() catch return 1;
    const arg2 = args.arg2() catch return 1;

    entry.update(.any, 0, @intFromPtr(arg0) + @intFromPtr(arg1) + arg2) catch return 1;
    return 0;
}

export fn test_kretprobe(args: *tracked_func.Ctx()) linksection(tracked_func.exit_section()) callconv(.C) c_long {
    exit.update(.any, 0, args.ret() catch return 1) catch return 1;
    return 0;
}
