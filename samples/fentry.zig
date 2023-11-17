const std = @import("std");
const bpf = @import("bpf");

var entry = bpf.Map.ArrayMap("entry", u64, 1, 0).init();
var exit = bpf.Map.ArrayMap("exit", i64, 1, 0).init();

const tracked_func = bpf.Fentry{ .name = "path_listxattr" };

export fn test_fentry(args: *tracked_func.Ctx()) linksection(tracked_func.entry_section()) callconv(.C) c_long {
    entry.update(.any, 0, args.arg2);
    return 0;
}

export fn test_fexit(args: *tracked_func.Ctx()) linksection(tracked_func.exit_section()) callconv(.C) c_long {
    exit.update(.any, 0, args.ret);
    return 0;
}
