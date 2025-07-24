const std = @import("std");
const print = std.debug.print;
const libbpf = @cImport({
    @cInclude("libbpf.h");
});

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();

    const bytes align(64) = @embedFile("@bpf_prog").*;

    const obj = libbpf.bpf_object__open_mem(&bytes, bytes.len, null);
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
        const my_pid = libbpf.bpf_object__find_map_by_name(obj, "my_pid").?;
        // map[0] = current pid
        const k: u32 = 0;
        const v: u32 = std.Thread.getCurrentId();
        ret = libbpf.bpf_map__update_elem(my_pid, &k, @sizeOf(@TypeOf(k)), &v, @sizeOf(@TypeOf(v)), 0);
        if (ret != 0) {
            print("failed update map element: {}\n", .{std.posix.errno(-1)});
            return error.MAP_UPDATE;
        }

        const link = libbpf.bpf_program__attach(prog) orelse {
            print("failed to attach prog {s}: {}\n", .{ libbpf.bpf_program__name(prog), std.posix.errno(-1) });
            return error.ATTACH;
        };
        defer _ = libbpf.bpf_link__destroy(link);

        // setup events perf buffer
        const events = libbpf.bpf_object__find_map_by_name(obj, "events").?;

        const perf_buf = libbpf.perf_buffer__new(libbpf.bpf_map__fd(events), 1, on_sample, null, null, null).?;
        defer libbpf.perf_buffer__free(perf_buf);

        std.Thread.sleep(11);

        ret = libbpf.perf_buffer__consume(perf_buf);
        if (ret != 0) {
            print("failed consume perf buffer: {}\n", .{std.posix.errno(-1)});
            return error.PERF_BUF;
        }
    }
}

fn on_sample(_: ?*anyopaque, cpu: c_int, data: ?*anyopaque, _: u32) callconv(.c) void {
    const s = std.mem.sliceTo(@as([*c]const u8, @ptrCast(data)), 0);

    print("Receive {s} from CPU{}\n", .{ s, cpu });
}
