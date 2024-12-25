const std = @import("std");
const print = std.debug.print;
const libbpf = @cImport({
    @cInclude("libbpf.h");
});
const libelf = @cImport({
    @cInclude("libelf.h");
});
const comm = @import("comm.zig");
const bpf = @import("bpf");
const vmlinux = @import("vmlinux");
const TRACE_RECORD = comm.TRACE_RECORD;
const STACK_TRACE = bpf.Map.STACK_TRACE;
const is_pointer = bpf.Args.is_pointer;
const cast = bpf.Args.cast;
const process = std.process;

const tracing_funcs = @import("@build_options").tracing_funcs;
const TF = @TypeOf(tracing_funcs[0]);

var exiting = false;
var debug = false;

fn dbg_printf(level: libbpf.libbpf_print_level, fmt: [*c]const u8, args: @typeInfo(@typeInfo(@typeInfo(libbpf.libbpf_print_fn_t).optional.child).pointer.child).@"fn".params[2].type.?) callconv(.C) c_int {
    if (!debug and level == libbpf.LIBBPF_DEBUG) return 0;

    return libbpf.vdprintf(std.io.getStdErr().handle, fmt, args);
}

fn usage() void {
    print(
        \\ Usage:
        \\ --timeout [seconds]
        \\ --help
        \\ --debug
        \\ --vmlinux [/path/to/vmlinux]
    ++ "\n", .{});
}

fn nextArg(args: []const []const u8, idx: *usize) ?[]const u8 {
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

    const bytes = @embedFile("@bpf_prog");

    var seconds: ?usize = null;
    var vmlinux_path: ?[]const u8 = null;
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
        } else if (std.mem.eql(u8, arg, "--vmlinux")) {
            vmlinux_path = nextArg(args, &arg_idx) orelse {
                usage();
                return error.ARGS;
            };
        } else {
            print("unknown parameter\n", .{});
            usage();
            return error.ARGS;
        }
    }

    _ = libbpf.libbpf_set_print(dbg_printf);

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

    var ksyms = Ksyms.init(allocator) catch null;
    defer if (ksyms) |*ks| ks.deinit();

    const stext_runtime: ?u64 = if (ksyms) |*ks| ks.stext_addr else null;
    var add2line = if (vmlinux_path) |p| Addr2Line.init(allocator, p, stext_runtime) catch null else null;
    defer if (add2line) |*al| al.deinit();

    var ctx: Ctx = .{
        .stdout = std.io.getStdOut().writer(),
        .stackmap = libbpf.bpf_object__find_map_by_name(obj, "stackmap").?,
        .al = add2line,
        .allocator = allocator,
        .ksyms = ksyms,
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
    print("Tracing...\n", .{});
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

fn setup_ctrl_c() void {
    const act = std.posix.Sigaction{
        .handler = .{ .handler = interrupt_handler },
        .mask = std.posix.empty_sigset,
        .flags = 0,
    };
    std.posix.sigaction(std.posix.SIG.INT, &act, null);
}

const Ctx = struct {
    stdout: std.fs.File.Writer,
    stackmap: *libbpf.bpf_map,
    al: ?Addr2Line,
    ksyms: ?Ksyms,
    allocator: std.mem.Allocator,
};

fn on_sample(_ctx: ?*anyopaque, data: ?*anyopaque, _: usize) callconv(.C) c_int {
    const ctx: *Ctx = @alignCast(@ptrCast(_ctx));
    const record: *TRACE_RECORD = @alignCast(@ptrCast(data.?));

    // kprobes at first, then syscalls
    switch (record.id) {
        inline 0...tracing_funcs.len - 1 => |i| {
            Args(tracing_funcs[i]).print(record, ctx.stdout);

            if (record.stack_id >= 0) {
                var entries: STACK_TRACE = undefined;
                if (libbpf.bpf_map__lookup_elem(ctx.stackmap, &record.stack_id, @sizeOf(u32), &entries, @sizeOf(@TypeOf(entries)), 0) != 0) {
                    return -1;
                }

                ctx.stdout.print("stack:\n", .{}) catch return -1;
                for (entries) |entry| {
                    if (entry == 0) break;

                    ctx.stdout.print("0x{x}", .{entry}) catch return -1;
                    if (ctx.ksyms) |*ksyms| {
                        if (ksyms.find(entry)) |sym| {
                            ctx.stdout.print(" {s}", .{sym.name}) catch return -1;
                            if (entry > sym.addr) {
                                ctx.stdout.print("+0x{x}", .{entry - sym.addr}) catch return -1;
                            }
                        }
                    }
                    if (ctx.al) |*al| {
                        if (al.find(entry)) |l| {
                            ctx.stdout.print(" {s}:{d}:{d}", .{ l.file_name, l.line, l.column }) catch return -1;
                            ctx.allocator.free(l.file_name);
                        }
                    }
                    ctx.stdout.print("\n", .{}) catch return -1;
                }
            }
        },

        else => ctx.stdout.print("Unknown function id: {}\n", .{record.id}) catch return -1,
    }

    return 0;
}

fn Args(comptime tf: TF) type {
    return struct {
        pub fn print(
            record: *const TRACE_RECORD,
            writer: anytype,
        ) void {
            const pid: u32 = @truncate(record.tpid);

            writer.print("pid: {}, {s} {s} {s}:\n", .{ pid, if (tf.kind == .kprobe) "kprobe" else "syscall", tf.name, if (record.entry) "enter" else "exit" }) catch {};
            var extra: usize = @intFromPtr(record) + @sizeOf(TRACE_RECORD);
            if (record.entry) {
                inline for (tf.args) |spec| {
                    if (comptime std.mem.startsWith(u8, spec, "arg")) {
                        const Arg = comm.Arg(tf.name, tf.kind == .syscall);
                        const T = Arg.Field(spec);
                        const placeholder = comptime Arg.placeholder(spec);
                        const is_string = comptime std.mem.eql(u8, placeholder, "{s}");
                        const v: *align(1) const T = @ptrFromInt(extra);
                        writer.print("{s}: " ++ placeholder ++ "\n", .{ spec, if (is_string) std.mem.sliceTo(v, 0) else v.* }) catch {};
                        extra += @sizeOf(T);
                    }
                }
            } else {
                inline for (tf.args) |spec| {
                    if (comptime std.mem.startsWith(u8, spec, "ret")) {
                        const Arg = comm.Arg(tf.name, tf.kind == .syscall);
                        const T = Arg.Field(spec);
                        const placeholder = comptime Arg.placeholder(spec);
                        const is_string = comptime std.mem.eql(u8, placeholder, "{s}");
                        const v: *align(1) const T = @ptrFromInt(extra);
                        writer.print("{s}: " ++ placeholder ++ "\n", .{ spec, if (is_string) std.mem.sliceTo(v, 0) else v.* }) catch {};
                        extra += @sizeOf(T);
                    }
                }
            }
        }
    };
}

const Ksyms = struct {
    const Self = @This();

    pub const Entry = struct {
        addr: u64,
        name: []const u8,
    };

    allocator: std.mem.Allocator,
    syms: []Entry, // in address asending order
    stext_addr: u64,

    pub fn init(allocator: std.mem.Allocator) !Self {
        const f = try std.fs.openFileAbsolute("/proc/kallsyms", .{});
        defer f.close();
        var br = std.io.bufferedReader(f.reader());
        const r = br.reader();
        var entries = std.ArrayList(Entry).init(allocator);
        errdefer entries.deinit();
        var stext: ?u64 = null;

        while (try r.readUntilDelimiterOrEofAlloc(allocator, '\n', std.math.maxInt(usize))) |line| {
            var it = std.mem.tokenizeScalar(u8, line, ' ');
            const addr = try std.fmt.parseInt(u64, it.next().?, 16);
            _ = it.next().?; // type
            const name = it.next().?;
            try entries.append(.{ .name = name, .addr = addr });
            if (std.mem.eql(u8, name, "_stext")) stext = addr;
        }

        return .{
            .allocator = allocator,
            .syms = try entries.toOwnedSlice(),
            .stext_addr = stext.?,
        };
    }

    fn compareAddr(addr: u64, entry: Entry) std.math.Order {
        return std.math.order(entry.addr, addr);
    }

    pub fn find(self: *const Self, addr: u64) ?Entry {
        const i = std.sort.lowerBound(Entry, self.syms, addr, compareAddr);
        if (i == self.syms.len) return null;

        // return the last smaller one if the result is larger than expected
        if (self.syms[i].addr > addr) {
            return self.syms[i - 1];
        } else return self.syms[i];
    }

    pub fn deinit(self: *Self) void {
        self.allocator.free(self.syms);
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
