const std = @import("std");
const bpf = @import("bpf");

var ret = bpf.Map.ArrayMap("ret", usize, 1, 0).init();

const tracked_func = bpf.Fentry{ .name = "path_listxattr" };

var n: usize = 0;

export fn fentry(args: *tracked_func.Ctx()) linksection(tracked_func.entry_section()) callconv(.C) c_long {
    n +|= args.arg2;
    ret.update(.any, 0, n) catch {};
    return 0;
}

export fn fexit(args: *tracked_func.Ctx()) linksection(tracked_func.exit_section()) callconv(.C) c_long {
    n +|= @intCast(usize, args.ret);
    ret.update(.any, 0, n) catch {};
    return 0;
}
