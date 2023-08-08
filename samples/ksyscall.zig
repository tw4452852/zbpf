const std = @import("std");
const bpf = @import("bpf");

var entry = bpf.Map.ArrayMap("entry", u64, 1, 0).init();
var exit = bpf.Map.ArrayMap("exit", i64, 1, 0).init();

const tracked_syscall = bpf.Ksyscall{ .name = "getxattr" };

export fn test_ksyscall(args: *tracked_syscall.Ctx()) linksection(tracked_syscall.entry_section()) callconv(.C) c_long {
    const arg0 = args.arg0() catch return -1;
    const arg1 = args.arg1() catch return -1;
    const arg2 = args.arg2() catch return -1;
    const arg3 = args.arg3() catch return -1;
    entry.update(.any, 0, arg0 + arg1 + arg2 + arg3) catch return -2;
    return 0;
}

export fn test_kretsyscall(args: *tracked_syscall.Ctx()) linksection(tracked_syscall.exit_section()) callconv(.C) c_long {
    const ret = args.ret();
    exit.update(.any, 0, @intCast(ret)) catch return -2;
    return 0;
}
