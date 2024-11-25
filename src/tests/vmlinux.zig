test {
    @setEvalBranchQuota(1000000);
    @import("std").testing.refAllDeclsRecursive(@import("vmlinux"));
}
