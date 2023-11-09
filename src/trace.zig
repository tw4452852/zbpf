const std = @import("std");
const print = std.debug.print;
const libbpf = @cImport({
    @cInclude("libbpf.h");
});
const bpf = @import("bpf");
const vmlinux = @import("vmlinux");
const TRACE_RECORD = bpf.Args.TRACE_RECORD;
const hasFn = std.meta.trait.hasFn;
const is_pointer = bpf.Args.is_pointer;
const cast = bpf.Args.cast;

const kprobes = @import("build_options").kprobes;
const syscalls = @import("build_options").syscalls;

var exiting = false;

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();

    const allocator = arena.allocator();

    const obj_bytes = @embedFile("@bpf_prog");
    const bytes = try allocator.dupe(u8, obj_bytes);
    defer allocator.free(bytes);

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
            print("failed to attach prog {s}: {}\n", .{ libbpf.bpf_program__name(prog), std.os.errno(-1) });
            return error.ATTACH;
        });
    }

    // setup events ring buffer
    const events = libbpf.bpf_object__find_map_by_name(obj, "events").?;
    const ring_buf = libbpf.ring_buffer__new(libbpf.bpf_map__fd(events), on_sample, null, null).?;
    defer libbpf.ring_buffer__free(ring_buf);

    try setup_ctrl_c();
    while (!exiting) {
        ret = libbpf.ring_buffer__poll(ring_buf, 100);

        if (ret < 0) {
            break;
        }
    }
}

fn interrupt_handler(_: c_int) callconv(.C) void {
    exiting = true;
}

fn setup_ctrl_c() !void {
    const act = std.os.Sigaction{
        .handler = .{ .handler = interrupt_handler },
        .mask = std.os.empty_sigset,
        .flags = 0,
    };
    try std.os.sigaction(std.os.SIG.INT, &act, null);
}

fn on_sample(_: ?*anyopaque, _data: ?*anyopaque, _: usize) callconv(.C) c_int {
    const record: *TRACE_RECORD = @alignCast(@ptrCast(_data.?));

    // kprobes at first, then syscalls
    switch (record.id) {
        inline 0...(if (kprobes.len > 0) kprobes.len - 1 else 0) => |i| if (kprobes.len > 0) {
            const func_name = kprobes[i];
            const tracked_func = bpf.Kprobe{ .name = func_name };
            const T = tracked_func.Ctx();
            const ctx: *T = @ptrCast(&record.regs);
            const pid: u32 = @truncate(record.tpid);

            print("pid: {}, kprobe {s}: ", .{ pid, func_name });
            if (comptime hasFn("arg0")(T)) {
                const v = ctx.arg0();

                print("arg0: " ++ (if (is_pointer(@TypeOf(v))) "{any}" else "{}"), .{v});
            }
            if (comptime hasFn("arg1")(T)) {
                const v = ctx.arg1();

                print(", arg1: " ++ (if (is_pointer(@TypeOf(v))) "{any}" else "{}"), .{v});
            }
            if (comptime hasFn("arg2")(T)) {
                const v = ctx.arg2();

                print(", arg2: " ++ (if (is_pointer(@TypeOf(v))) "{any}" else "{}"), .{v});
            }
            if (comptime hasFn("arg3")(T)) {
                const v = ctx.arg3();

                print(", arg3: " ++ (if (is_pointer(@TypeOf(v))) "{any}" else "{}"), .{v});
            }
            if (comptime hasFn("arg4")(T)) {
                const v = ctx.arg4();

                print("arg4: " ++ (if (is_pointer(@TypeOf(v))) "{any}" else "{}"), .{v});
            }
            if (comptime hasFn("ret")(T)) {
                const v = ctx.ret();

                print(", ret: " ++ (if (is_pointer(@TypeOf(v))) "{any}" else "{}"), .{v});
            }
            print("\n", .{});
        },

        inline kprobes.len...(if (syscalls.len > 0) kprobes.len + syscalls.len - 1 else kprobes.len) => |i| if (syscalls.len > 0) {
            // TODO: get syscall prototype
            const name = syscalls[i - kprobes.len];
            const func_name = "sys_" ++ name;
            const pid: u32 = @truncate(record.tpid);

            if (!@hasDecl(vmlinux, func_name)) {
                print("can't determine the prototype of syscall {s}, dump all possible arguments w/o type\n", .{name});
                print("pid: {}, syscall {s}: arg0: 0x{x}, arg1: 0x{x}, arg2: 0x{x}, arg3: 0x{x}, arg4: 0x{x}, ret: 0x{x}\n", .{ pid, name, record.regs.arg0_ptr().*, record.regs.arg1_ptr().*, record.regs.arg2_ptr().*, record.regs.arg3_ptr(true).*, record.regs.arg4_ptr().*, record.regs.ret_ptr().* });
            } else {
                const f = @typeInfo(@TypeOf(@field(vmlinux, func_name)));
                print("pid: {}, syscall {s}: ", .{ pid, name });
                if (f.Fn.params.len > 0) {
                    const RET = f.Fn.params[0].type.?;
                    print("arg0: " ++ (if (is_pointer(RET)) "{any}" else "{}"), .{cast(RET, record.regs.arg0_ptr().*)});
                }
                if (f.Fn.params.len > 1) {
                    const RET = f.Fn.params[1].type.?;
                    print(", arg1: " ++ (if (is_pointer(RET)) "{any}" else "{}"), .{cast(RET, record.regs.arg1_ptr().*)});
                }
                if (f.Fn.params.len > 2) {
                    const RET = f.Fn.params[2].type.?;
                    print(", arg2: " ++ (if (is_pointer(RET)) "{any}" else "{}"), .{cast(RET, record.regs.arg2_ptr().*)});
                }
                if (f.Fn.params.len > 3) {
                    const RET = f.Fn.params[3].type.?;
                    print(", arg3: " ++ (if (is_pointer(RET)) "{any}" else "{}"), .{cast(RET, record.regs.arg3_ptr().*)});
                }
                if (f.Fn.params.len > 4) {
                    const RET = f.Fn.params[4].type.?;
                    print(", arg4: " ++ (if (is_pointer(RET)) "{any}" else "{}"), .{cast(RET, record.regs.arg4_ptr().*)});
                }
                if (f.Fn.return_type.? != void) {
                    const RET = f.Fn.return_type.?;
                    print(", ret: " ++ (if (is_pointer(RET)) "{any}" else "{}"), .{cast(RET, record.regs.ret_ptr().*)});
                }
                print("\n", .{});
            }
        },

        else => print("Unknown function id: {}\n", .{record.id}),
    }

    return 0;
}
