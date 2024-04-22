const std = @import("std");
const print = std.debug.print;
const libbpf = @cImport({
    @cInclude("libbpf.h");
});
const bpf = @import("bpf");
const vmlinux = @import("vmlinux");
const TRACE_RECORD = bpf.Args.TRACE_RECORD;
const is_pointer = bpf.Args.is_pointer;
const cast = bpf.Args.cast;
const process = std.process;

const kprobes = @import("build_options").kprobes;
const syscalls = @import("build_options").syscalls;

var exiting = false;

fn usage() void {
    print(
        \\ Usage:
        \\ --timeout [seconds]
        \\ --help
    ++ "\n", .{});
}

fn nextArg(args: [][]const u8, idx: *usize) ?[]const u8 {
    if (idx.* >= args.len) return null;
    defer idx.* += 1;
    return args[idx.*];
}

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();

    const allocator = arena.allocator();

    const args = try process.argsAlloc(allocator);
    defer process.argsFree(allocator, args);
    var arg_idx: usize = 1; // skip exe name

    const obj_bytes = @embedFile("@bpf_prog");
    const bytes = try allocator.dupe(u8, obj_bytes);
    defer allocator.free(bytes);

    var seconds: ?usize = null;
    while (nextArg(args, &arg_idx)) |arg| {
        if (std.mem.eql(u8, arg, "--timeout")) {
            const s = nextArg(args, &arg_idx) orelse {
                usage();
                return error.ARGS;
            };
            seconds = try std.fmt.parseUnsigned(usize, s, 0);
        } else if (std.mem.eql(u8, arg, "--help")) {
            usage();
            return;
        } else {
            print("unknown parameter\n", .{});
            usage();
            return error.ARGS;
        }
    }

    const obj = libbpf.bpf_object__open_mem(bytes.ptr, bytes.len, null);
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

    var links = std.ArrayList(*libbpf.bpf_link).init(allocator);
    defer {
        for (links.items) |link| {
            _ = libbpf.bpf_link__destroy(link);
        }
        links.deinit();
    }

    var cur_prog: ?*libbpf.bpf_program = null;
    while (libbpf.bpf_object__next_program(obj, cur_prog)) |prog| : (cur_prog = prog) {
        try links.append(libbpf.bpf_program__attach(prog) orelse {
            print("failed to attach prog {s}: {}\n", .{ libbpf.bpf_program__name(prog), std.posix.errno(-1) });
            return error.ATTACH;
        });
    }

    var ctx: Ctx = .{
        .stdout = std.io.getStdOut().writer(),
    };

    // setup events ring buffer
    const events = libbpf.bpf_object__find_map_by_name(obj, "events").?;
    const ring_buf = libbpf.ring_buffer__new(libbpf.bpf_map__fd(events), on_sample, &ctx, null).?;
    defer libbpf.ring_buffer__free(ring_buf);

    try setup_ctrl_c();
    const begin_ts = std.time.timestamp();
    while (!exiting) {
        ret = libbpf.ring_buffer__poll(ring_buf, 100);

        if (ret < 0) {
            return error.POLL;
        }

        if (seconds) |timeout| {
            const cur_ts = std.time.timestamp();
            if (cur_ts - begin_ts > timeout) break;
        }
    }
}

fn interrupt_handler(_: c_int) callconv(.C) void {
    exiting = true;
}

fn setup_ctrl_c() !void {
    const act = std.posix.Sigaction{
        .handler = .{ .handler = interrupt_handler },
        .mask = std.posix.empty_sigset,
        .flags = 0,
    };
    try std.posix.sigaction(std.posix.SIG.INT, &act, null);
}

const Ctx = struct {
    stdout: std.fs.File.Writer,
};

fn on_sample(_ctx: ?*anyopaque, data: ?*anyopaque, _: usize) callconv(.C) c_int {
    const ctx: *Ctx = @alignCast(@ptrCast(_ctx));
    const record: *TRACE_RECORD = @alignCast(@ptrCast(data.?));

    // kprobes at first, then syscalls
    switch (record.id) {
        inline 0...kprobes.len + syscalls.len - 1 => |i| {
            const for_kprobe = i < kprobes.len;
            const func_name = if (for_kprobe) kprobes[i] else syscalls[i - kprobes.len];
            const tracked_func = if (for_kprobe) bpf.Kprobe{ .name = func_name } else bpf.Ksyscall{ .name = func_name };
            const T = tracked_func.Ctx();
            const args: *T = @ptrCast(&record.regs);
            const pid: u32 = @truncate(record.tpid);

            ctx.stdout.print("pid: {}, {s} {s}: ", .{ pid, if (for_kprobe) "kprobe" else "syscall", func_name }) catch return -1;
            if (comptime @hasDecl(T, "arg0")) {
                const v = args.arg0();

                ctx.stdout.print("arg0: " ++ (if (is_pointer(@TypeOf(v))) "{any}" else "{}"), .{v}) catch return -1;
            }
            if (comptime @hasDecl(T, "arg1")) {
                const v = args.arg1();

                ctx.stdout.print(", arg1: " ++ (if (is_pointer(@TypeOf(v))) "{any}" else "{}"), .{v}) catch return -1;
            }
            if (comptime @hasDecl(T, "arg2")) {
                const v = args.arg2();

                ctx.stdout.print(", arg2: " ++ (if (is_pointer(@TypeOf(v))) "{any}" else "{}"), .{v}) catch return -1;
            }
            if (comptime @hasDecl(T, "arg3")) {
                const v = args.arg3();

                ctx.stdout.print(", arg3: " ++ (if (is_pointer(@TypeOf(v))) "{any}" else "{}"), .{v}) catch return -1;
            }
            if (comptime @hasDecl(T, "arg4")) {
                const v = args.arg4();

                ctx.stdout.print("arg4: " ++ (if (is_pointer(@TypeOf(v))) "{any}" else "{}"), .{v}) catch return -1;
            }
            if (comptime @hasDecl(T, "ret")) {
                const v = args.ret();

                ctx.stdout.print(", ret: " ++ (if (is_pointer(@TypeOf(v))) "{any}" else "{}"), .{v}) catch return -1;
            }
            ctx.stdout.print("\n", .{}) catch return -1;
        },

        else => ctx.stdout.print("Unknown function id: {}\n", .{record.id}) catch return -1,
    }

    return 0;
}
