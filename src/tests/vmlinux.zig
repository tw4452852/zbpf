const std = @import("std");
const vmlinux = @import("vmlinux");

test "vmlinux_compile" {
    @setEvalBranchQuota(1000000);
    std.testing.refAllDeclsRecursive(vmlinux);
}
