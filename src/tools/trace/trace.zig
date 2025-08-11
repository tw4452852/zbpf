const std = @import("std");
const print = std.debug.print;
const libbpf = @cImport({
    @cInclude("libbpf.h");
});
const libelf = @cImport({
    @cInclude("libelf.h");
});
const perf_event = @cImport({
    @cInclude("linux/perf_event.h");
});
const vmlinux = @import("vmlinux");
const comm = @import("comm.zig");
const bpf = @import("bpf");
const TRACE_RECORD = comm.TRACE_RECORD;
const STACK_TRACE = bpf.Map.STACK_TRACE;
const is_pointer = bpf.Args.is_pointer;
const cast = bpf.Args.cast;
const process = std.process;

const tracing_funcs = @import("@build_options").tracing_funcs;
const TraceFunc = @import("@build_options").TraceFunc;

var exiting = false;
var debug = false;
var testing = false;

fn dbg_printf(level: libbpf.libbpf_print_level, fmt: [*c]const u8, args: @typeInfo(@typeInfo(@typeInfo(libbpf.libbpf_print_fn_t).optional.child).pointer.child).@"fn".params[2].type.?) callconv(.c) c_int {
    if (!debug and level == libbpf.LIBBPF_DEBUG) return 0;

    return libbpf.vdprintf(std.fs.File.stderr().handle, fmt, args);
}

fn usage() void {
    print(
        \\ Usage:
        \\ --timeout [seconds]
        \\ --help
        \\ --debug
        \\ --testing
        \\ --lbr
        \\ --vmlinux [/path/to/vmlinux]
        \\ --count [n]
    ++ "\n", .{});
}

fn nextArg(args: []const []const u8, idx: *usize) ?[]const u8 {
    if (idx.* >= args.len) return null;
    defer idx.* += 1;
    return args[idx.*];
}

// Just for testing
export fn testing_call(a: u32, b: u32) u32 {
    return testing_call_nest(a, b);
}
export fn testing_call_nest(a: u32, b: u32) u32 {
    return a + b;
}

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();

    const allocator = arena.allocator();

    const args = try process.argsAlloc(allocator);
    defer process.argsFree(allocator, args);
    var arg_idx: usize = 1; // skip exe name

    var seconds: ?usize = null;
    var vmlinux_path: ?[]const u8 = null;
    var max_count: ?usize = null;
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
        } else if (std.mem.eql(u8, arg, "--debug")) {
            debug = true;
        } else if (std.mem.eql(u8, arg, "--testing")) {
            testing = true;
        } else if (std.mem.eql(u8, arg, "--vmlinux")) {
            vmlinux_path = nextArg(args, &arg_idx) orelse {
                usage();
                return error.ARGS;
            };
        } else if (std.mem.eql(u8, arg, "--count")) {
            const s = nextArg(args, &arg_idx) orelse {
                usage();
                return error.ARGS;
            };
            max_count = try std.fmt.parseUnsigned(usize, s, 0);
        } else {
            print("unknown parameter\n", .{});
            usage();
            return error.ARGS;
        }
    }

    _ = libbpf.libbpf_set_print(dbg_printf);

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

    var links = std.ArrayList(*libbpf.bpf_link).init(allocator);
    defer {
        for (links.items) |link| {
            _ = libbpf.bpf_link__destroy(link);
        }
        links.deinit();
    }

    var ksyms = Ksyms.init(allocator) catch null;
    defer if (ksyms) |*ks| ks.deinit(allocator);

    var lbr_opt = LBR.init(allocator) catch null;
    defer if (lbr_opt) |*lbr| lbr.deinit();

    const stext_runtime: ?u64 = if (ksyms) |*ks| ks.stext_addr else null;
    var add2line_opt = if (vmlinux_path) |p| Addr2Line.init(allocator, p, stext_runtime) catch null else null;
    defer if (add2line_opt) |*al| al.deinit();

    var sw = std.fs.File.stdout().writerStreaming(&.{});
    var ctx: Ctx = .{
        .stdout = sw,
        .stackmap = libbpf.bpf_object__find_map_by_name(obj, "stackmap"),
        .al = if (add2line_opt) |*al| al else null,
        .ksyms = if (ksyms) |*ks| ks else null,
        .allocator = allocator,
    };
    // setup events ring buffer
    const events = libbpf.bpf_object__find_map_by_name(obj, "events").?;
    const ring_buf = libbpf.ring_buffer__new(libbpf.bpf_map__fd(events), on_sample, &ctx, null).?;
    defer libbpf.ring_buffer__free(ring_buf);

    // attach programs
    var cur_prog: ?*libbpf.bpf_program = null;
    while (libbpf.bpf_object__next_program(obj, cur_prog)) |prog| : (cur_prog = prog) {
        try links.append(libbpf.bpf_program__attach(prog) orelse {
            print("failed to attach prog {s}: {}\n", .{ libbpf.bpf_program__name(prog), std.posix.errno(-1) });
            return error.ATTACH;
        });
    }

    setup_ctrl_c();
    try sw.interface.writeAll("Tracing...\n");
    if (testing) {
        _ = testing_call(1, 2);
    }
    const begin_ts = std.time.timestamp();
    var consumed: usize = 0;
    while (!exiting) {
        if (max_count) |max| {
            ret = libbpf.ring_buffer__consume_n(ring_buf, max - consumed);
        } else {
            ret = libbpf.ring_buffer__poll(ring_buf, 100);
        }

        if (ret < 0) {
            return error.POLL;
        }
        consumed += @intCast(ret);

        if (max_count) |max| {
            if (consumed >= max) break;
        }

        if (seconds) |timeout| {
            const cur_ts = std.time.timestamp();
            if (cur_ts - begin_ts > timeout) break;
        }
    }
}

fn interrupt_handler(_: c_int) callconv(.c) void {
    exiting = true;
}

fn setup_ctrl_c() void {
    const act = std.posix.Sigaction{
        .handler = .{ .handler = interrupt_handler },
        .mask = undefined,
        .flags = 0,
    };
    std.posix.sigaction(std.posix.SIG.INT, &act, null);
}

const Ctx = struct {
    stdout: std.fs.File.Writer,
    stackmap: ?*libbpf.bpf_map,
    al: ?*Addr2Line,
    ksyms: ?*const Ksyms,
    allocator: std.mem.Allocator,
};

fn on_sample(_ctx: ?*anyopaque, data: ?*anyopaque, _: usize) callconv(.c) c_int {
    const ctx: *Ctx = @ptrCast(@alignCast(_ctx));
    const record: *TRACE_RECORD = @ptrCast(@alignCast(data.?));

    // kprobes at first, then syscalls
    switch (record.id) {
        inline 0...tracing_funcs.len - 1 => |i| {
            Args(tracing_funcs[i]).print(record, &ctx.stdout);

            if (record.stack_id >= 0) {
                var entries: STACK_TRACE = undefined;
                if (libbpf.bpf_map__lookup_elem(ctx.stackmap, &record.stack_id, @sizeOf(u32), &entries, @sizeOf(@TypeOf(entries)), 0) != 0) {
                    return -1;
                }

                ctx.stdout.interface.writeAll("Stack:\n") catch return -1;
                for (entries) |entry| {
                    if (entry == 0) break;

                    ctx.stdout.interface.print("0x{x}", .{entry}) catch return -1;
                    const syms_opt = if (tracing_funcs[i].kind == .uprobe) null else ctx.ksyms;
                    if (syms_opt) |syms| {
                        if (syms.find(entry)) |sym| {
                            ctx.stdout.interface.print(" {s}", .{sym.name}) catch return -1;
                            if (entry > sym.addr) {
                                ctx.stdout.interface.print("+0x{x}", .{entry - sym.addr}) catch return -1;
                            }
                        }
                    }
                    const al_opt = if (tracing_funcs[i].kind == .uprobe) null else ctx.al;
                    if (al_opt) |al| {
                        if (al.find(entry)) |l| {
                            ctx.stdout.interface.print(" {s}:{d}:{d}", .{ l.file_name, l.line, l.column }) catch return -1;
                            ctx.allocator.free(l.file_name);
                        }
                    }
                    ctx.stdout.interface.print("\n", .{}) catch return -1;
                }
            }

            if (record.lbr_size > 0) {
                const lbrs: [*]align(1) vmlinux.perf_branch_entry = @ptrFromInt(@intFromPtr(record) + @sizeOf(TRACE_RECORD) + record.arg_size);
                ctx.stdout.interface.writeAll("LBRs:\n") catch return -1;
                for (0..@divExact(@as(usize, @intCast(record.lbr_size)), @sizeOf(vmlinux.perf_branch_entry))) |idx| {
                    ctx.stdout.interface.print("{}: 0x{x} -> 0x{x}\n", .{ idx, lbrs[idx].from, lbrs[idx].to }) catch return -1;
                }
            }
        },

        else => ctx.stdout.interface.print("Unknown function id: {}\n", .{record.id}) catch return -1,
    }

    return 0;
}

fn Args(comptime tf: TraceFunc) type {
    return struct {
        pub fn print(
            record: *const TRACE_RECORD,
            writer: anytype,
        ) void {
            const pid: u32 = @truncate(record.tpid);

            writer.interface.print("pid: {}, {s} {s} {s}:\n", .{ pid, @tagName(tf.kind), tf.name, if (record.entry) "enter" else "exit" }) catch {};
            var extra: usize = @intFromPtr(record) + @sizeOf(TRACE_RECORD);
            if (record.entry) {
                inline for (tf.args) |spec| {
                    if (comptime std.mem.startsWith(u8, spec, "arg")) {
                        const Arg = comm.Arg(tf.name, tf.kind);
                        const T = Arg.Field(spec);
                        const placeholder = comptime Arg.placeholder(spec);
                        const is_string = comptime std.mem.eql(u8, placeholder, "{s}");
                        const v: *align(1) const T = @ptrFromInt(extra);
                        writer.interface.print("{s}: " ++ placeholder ++ "\n", .{ spec, if (is_string) std.mem.sliceTo(v, 0) else v.* }) catch {};
                        extra += @sizeOf(T);
                    }
                }
            } else {
                inline for (tf.args) |spec| {
                    if (comptime std.mem.startsWith(u8, spec, "ret")) {
                        const Arg = comm.Arg(tf.name, tf.kind);
                        const T = Arg.Field(spec);
                        const placeholder = comptime Arg.placeholder(spec);
                        const is_string = comptime std.mem.eql(u8, placeholder, "{s}");
                        const v: *align(1) const T = @ptrFromInt(extra);
                        writer.interface.print("{s}: " ++ placeholder ++ "\n", .{ spec, if (is_string) std.mem.sliceTo(v, 0) else v.* }) catch {};
                        extra += @sizeOf(T);
                    }
                }
            }
        }
    };
}

const Ksyms = struct {
    pub const Entry = struct {
        addr: u64,
        name: []const u8,
    };

    syms: []Entry, // in address asending order
    stext_addr: u64,

    pub fn init(allocator: std.mem.Allocator) !Ksyms {
        const f = try std.fs.openFileAbsolute("/proc/kallsyms", .{});
        defer f.close();
        var line_buf: [256]u8 = undefined;
        var r = f.reader(&line_buf);
        var entries = std.ArrayList(Entry).init(allocator);
        errdefer entries.deinit();
        var stext: ?u64 = null;

        while (r.interface.takeDelimiterExclusive('\n')) |line| {
            var it = std.mem.tokenizeScalar(u8, line, ' ');
            const addr = try std.fmt.parseInt(u64, it.next().?, 16);
            const t = it.next().?; // type
            if (!std.ascii.eqlIgnoreCase(t, "t")) continue;
            const name = it.next().?;
            try entries.append(.{ .name = try allocator.dupe(u8, name), .addr = addr });
            if (std.mem.eql(u8, name, "_stext")) stext = addr;
        } else |err| switch (err) {
            error.EndOfStream => {},
            else => |e| return e,
        }

        std.mem.sortUnstable(Entry, entries.items, {}, struct {
            fn lessThan(ctx: void, a: Entry, b: Entry) bool {
                _ = ctx;
                return a.addr < b.addr;
            }
        }.lessThan);

        return .{
            .syms = try entries.toOwnedSlice(),
            .stext_addr = stext.?,
        };
    }

    fn compareAddr(addr: u64, entry: Entry) std.math.Order {
        return std.math.order(addr, entry.addr);
    }

    pub fn find(self: *const Ksyms, addr: u64) ?Entry {
        const i = std.sort.lowerBound(Entry, self.syms, addr, compareAddr);
        if (i == self.syms.len) return null;

        // return the last smaller one if the result is larger than expected
        if (self.syms[i].addr > addr) {
            return self.syms[i - 1];
        } else return self.syms[i];
    }

    pub fn deinit(self: *Ksyms, allocator: std.mem.Allocator) void {
        for (self.syms) |sym| allocator.free(sym.name);
        allocator.free(self.syms);
        self.* = undefined;
    }
};

const Addr2Line = struct {
    const Self = @This();

    module: std.debug.Dwarf.ElfModule,
    allocator: std.mem.Allocator,
    offset: u64,

    pub fn init(allocator: std.mem.Allocator, vmlinux_path: []const u8, stext_runtime_opt: ?u64) !Self {
        var sections: std.debug.Dwarf.SectionArray = std.debug.Dwarf.null_section_array;
        const module = std.debug.Dwarf.ElfModule.loadPath(allocator, .{ .root_dir = std.Build.Cache.Directory.cwd(), .sub_path = vmlinux_path }, null, null, &sections, null) catch |err| {
            print("failed to load vmlinux debug info: {}\n", .{err});
            return err;
        };

        const offset: u64 = if (stext_runtime_opt) |stext_runtime| blk: {
            const f = try std.fs.openFileAbsolute(vmlinux_path, .{});
            defer f.close();
            const elf = libelf.elf_begin(f.handle, libelf.ELF_C_READ_MMAP, null).?;
            defer _ = libelf.elf_end(elf);

            var stridx: usize = undefined;
            const ret = libelf.elf_getshdrstrndx(elf, &stridx);
            if (ret != 0) {
                print("failed to get string section idx: {}\n", .{std.posix.errno(-1)});
                return error.PARSE;
            }

            var scn = libelf.elf_nextscn(elf, null);
            while (scn) |section| : (scn = libelf.elf_nextscn(elf, scn)) {
                const shdr: *libelf.Elf64_Shdr = libelf.elf64_getshdr(section) orelse {
                    print("failed to get section header: {}\n", .{std.posix.errno(-1)});
                    return error.PARSE;
                };
                const name = libelf.elf_strptr(elf, stridx, shdr.sh_name) orelse {
                    print("failed to get section name: {}\n", .{std.posix.errno(-1)});
                    return error.PARSE;
                };
                if (std.mem.eql(u8, name[0..".text".len], ".text")) {
                    break :blk stext_runtime - shdr.sh_addr;
                }
            } else unreachable;
        } else 0;

        return .{ .module = module, .allocator = allocator, .offset = offset };
    }

    pub fn find(self: *Self, addr: u64) ?std.debug.SourceLocation {
        return if (self.module.getSymbolAtAddress(self.allocator, addr - self.offset)) |sym| sym.source_location else |_| null;
    }

    pub fn deinit(self: *Self) void {
        self.module.deinit(self.allocator);
        self.* = undefined;
    }
};

const LBR = struct {
    fds: []std.posix.fd_t,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) !LBR {
        const num_cpus = libbpf.libbpf_num_possible_cpus();
        const fds = try allocator.alloc(std.posix.fd_t, @intCast(num_cpus));
        errdefer allocator.free(fds);
        for (fds, 0..) |*fd, cpu| {
            var attr: std.posix.system.perf_event_attr = .{
                .type = .HARDWARE,
                .sample_type = perf_event.PERF_SAMPLE_BRANCH_STACK,
                .branch_sample_type = perf_event.PERF_SAMPLE_BRANCH_USER | perf_event.PERF_SAMPLE_BRANCH_CALL,
            };
            const ret = std.os.linux.perf_event_open(&attr, -1, @intCast(cpu), -1, 0);
            if (@as(isize, @bitCast(ret)) < 0) return error.PERF_OPEN;
            fd.* = @intCast(ret);
            errdefer std.posix.close(fd.*);
        }
        return .{
            .fds = fds,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *LBR) void {
        for (self.fds) |fd| std.posix.close(fd);
        self.allocator.free(self.fds);
        self.* = undefined;
    }
};
