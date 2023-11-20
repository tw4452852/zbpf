const std = @import("std");
const root = @import("root.zig");
const print = std.debug.print;
const testing = std.testing;
const allocator = root.allocator;
const libbpf = root.libbpf;

test "exit" {
    const obj_bytes = @embedFile("@exit");
    const bytes = try allocator.dupe(u8, obj_bytes);
    defer allocator.free(bytes);

    _ = libbpf.libbpf_set_print(root.dbg_printf);

    const obj = libbpf.bpf_object__open_mem(bytes.ptr, bytes.len, null);
    if (obj == null) {
        print("failed to open bpf object: {}\n", .{std.os.errno(-1)});
        return error.OPEN;
    }
    defer libbpf.bpf_object__close(obj);

    var ret = libbpf.bpf_object__load(obj);
    if (ret != 0) {
        print("failed to load bpf object: {}\n", .{std.os.errno(-1)});
        return error.LOAD;
    }

    if (libbpf.bpf_object__next_program(obj, null)) |prog| {
        // run bpf program
        const fd = libbpf.bpf_program__fd(prog);
        var attr = std.mem.zeroInit(libbpf.bpf_test_run_opts, .{
            .sz = @sizeOf(libbpf.bpf_test_run_opts),
        });
        ret = libbpf.bpf_prog_test_run_opts(fd, &attr);
        if (ret != 0) {
            print("failed run prog: {}\n", .{std.os.errno(-1)});
            return error.RUN;
        }
        try testing.expectEqual(@as(c_long, 0), attr.retval);

        const f = try root.open_tracebuf_pipe();
        defer root.close_tracebuf_pipe(f);
        const r = f.reader();
        const l = try r.readUntilDelimiterAlloc(allocator, '\n', std.math.maxInt(u32));
        defer allocator.free(l);
        try testing.expectStringEndsWith(l, "trace_printk: error occur at samples/exit.zig:5 return 1");
    }
}
