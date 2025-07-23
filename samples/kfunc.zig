const std = @import("std");
const bpf = @import("bpf");
const vmlinux = @import("vmlinux");

const tracked_func = bpf.Fentry{ .name = "path_listxattr" };

extern fn bpf_task_acquire(*vmlinux.task_struct) ?*vmlinux.task_struct;
extern fn bpf_task_from_pid(i32) ?*vmlinux.task_struct;
extern fn bpf_task_release(*vmlinux.task_struct) void;

export fn test_kfunc(_: *tracked_func.Ctx()) linksection(tracked_func.entry_section()) callconv(.c) c_int {
    const tsk = bpf_task_from_pid(1) orelse return 0;
    defer bpf_task_release(tsk);

    const ref = bpf_task_acquire(tsk) orelse return 0;
    bpf_task_release(ref);

    return 0;
}
