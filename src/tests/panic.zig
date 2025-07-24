const std = @import("std");
const root = @import("root.zig");
const print = std.debug.print;
const testing = std.testing;
const allocator = root.allocator;
const libbpf = root.libbpf;

test "panic" {
    _ = libbpf.libbpf_set_print(root.dbg_printf);

    const path = try allocator.dupeZ(u8, @import("@build_options").prog_panic_path);
    defer allocator.free(path);
    const obj = libbpf.bpf_object__open(path);
    if (obj == null) {
        print("failed to open bpf object: {}\n", .{std.posix.errno(-1)});
        return error.OPEN;
    }
    defer libbpf.bpf_object__close(obj);

    var ret = libbpf.bpf_object__load(obj);
    if (ret != 0) {
        print("failed to load bpf object: {}\n", .{std.posix.errno(-1)});
        return error.LOAD;
    }

    if (libbpf.bpf_object__next_program(obj, null)) |prog| {
        const f = try root.open_tracebuf_pipe(true);
        defer root.close_tracebuf_pipe(f);

        // run bpf program
        const fd = libbpf.bpf_program__fd(prog);
        var buf: [32]u8 = undefined;
        var attr = std.mem.zeroInit(libbpf.bpf_test_run_opts, .{
            .sz = @sizeOf(libbpf.bpf_test_run_opts),
            .data_in = &buf,
            .data_size_in = 32,
            .data_out = &buf,
        });
        ret = libbpf.bpf_prog_test_run_opts(fd, &attr);
        if (ret != 0) {
            print("failed run prog: {}\n", .{std.posix.errno(-1)});
            return error.RUN;
        }
        try testing.expectEqual(@as(c_long, 0), attr.retval);

        var aw: std.Io.Writer.Allocating = .init(allocator);
        defer aw.deinit();
        var fb: [128]u8 = undefined;
        var fr = f.reader(&fb);
        _ = try std.Io.Reader.streamDelimiterLimit(&fr.interface, &aw.writer, '\n', .unlimited);

        try testing.expectStringEndsWith(aw.getWritten(), "trace_printk: Panic: test");
    }
}
