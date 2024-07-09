const std = @import("std");
const c = @cImport({
    @cInclude("libbpf.h");
    @cInclude("btf.h");
    @cInclude("libbpf_iter.h"); // this is libbpf's internal
    @cInclude("libelf.h");
});
const build_options = @import("build_options");

fn print(comptime fmt: []const u8, args: anytype) void {
    std.debug.print("btf_sanitizer:" ++ fmt, args);
}

fn dbg_print(comptime fmt: []const u8, args: anytype) void {
    if (build_options.debug) {
        print(fmt, args);
    }
}

fn libbpf_dbg_printf(level: c.libbpf_print_level, fmt: [*c]const u8, args: @typeInfo(@typeInfo(@typeInfo(c.libbpf_print_fn_t).Optional.child).Pointer.child).Fn.params[2].type.?) callconv(.C) c_int {
    if (!build_options.debug and level == c.LIBBPF_DEBUG) return 0;

    return c.vdprintf(std.io.getStdErr().handle, fmt, args);
}

// btf_sanitizer src_obj -o/path/to/dst_obj [-vmlinux/path/to/vmlinux]
pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();

    const allocator = arena.allocator();

    _ = c.libbpf_set_print(libbpf_dbg_printf);

    var it = std.process.args();
    _ = it.skip(); // skip process name
    var src_arg: ?[:0]const u8 = null;
    var dst_arg: ?[:0]const u8 = null;
    var vmlinux_arg: ?[:0]const u8 = null;
    while (it.next()) |arg| {
        if (std.mem.startsWith(u8, arg, "-o")) {
            dst_arg = dst_arg orelse arg[2..];
        } else if (std.mem.startsWith(u8, arg, "-vmlinux")) {
            vmlinux_arg = vmlinux_arg orelse arg[8..];
        } else {
            src_arg = if (src_arg) |_| {
                @panic("multiple src");
            } else arg;
        }
    }

    const src_obj_path = src_arg.?;
    const dst_obj_path = dst_arg.?;
    try std.fs.copyFileAbsolute(src_obj_path, dst_obj_path, .{});
    dbg_print("sanitize obj from {s} to {s}\n", .{ src_obj_path, dst_obj_path });

    const src_obj = try std.fs.openFileAbsolute(src_obj_path, .{ .mode = .read_only });
    defer src_obj.close();
    const dst_obj = try std.fs.openFileAbsolute(dst_obj_path, .{ .mode = .read_write });
    defer dst_obj.close();

    const src_btf = c.btf__parse(src_obj_path, null) orelse {
        print("failed to get source BTF: {}\n", .{std.posix.errno(-1)});
        return error.PARSE;
    };
    var sz: c_uint = undefined;

    var buf = c.btf__raw_data(src_btf, &sz);
    const dst_btf = c.btf__new(buf, sz) orelse {
        print("create empty dest BTF failed: {}\n", .{std.posix.errno(-1)});
        return error.PARSE;
    };
    defer c.btf__free(dst_btf);

    const elf = c.elf_begin(dst_obj.handle, c.ELF_C_RDWR, null) orelse {
        print("failed to open dst elf: {}\n", .{std.posix.errno(-1)});
        return error.PARSE;
    };
    defer {
        _ = c.elf_update(elf, c.ELF_C_WRITE);
        _ = c.elf_end(elf);
    }
    var stridx: usize = undefined;
    var ret = c.elf_getshdrstrndx(elf, &stridx);
    if (ret != 0) {
        print("failed to get string section idx: {}\n", .{std.posix.errno(-1)});
        return error.PARSE;
    }

    // sanitize
    _ = c.btf__find_str(dst_btf, ""); // ensure btf is in modifiable/splited state
    var externs_with_btf = std.StringHashMap(u32).init(allocator); // record external symbols which have BTF already
    defer externs_with_btf.deinit();
    // fix existing BTF
    for (0..c.btf__type_cnt(dst_btf)) |i| {
        const t: *c.btf_type = @constCast(c.btf__type_by_id(dst_btf, @intCast(i)));

        if ((c.btf_is_fwd(t) or c.btf_is_struct(t)) and t.name_off > 0) {
            // replace non-alphabet with '_'
            const name: [:0]u8 = @constCast(std.mem.sliceTo(c.btf__name_by_offset(dst_btf, t.name_off), 0));
            dbg_print("fix {s} type name {s}\n", .{ if (c.btf_is_fwd(t)) "forward" else "struct", name });
            for (name) |*ch| {
                if (!std.ascii.isAlphabetic(ch.*)) {
                    ch.* = '_';
                }
            }
        } else if (c.btf_is_ptr(t)) {
            // null pointer type name
            dbg_print("nullify pointer type name {s}\n", .{std.mem.sliceTo(c.btf__name_by_offset(dst_btf, t.name_off), 0)});
            t.name_off = 0;
        } else if (c.btf_is_func_proto(t)) {
            // add function parameter's name with 'argX' if missing
            const vlen: usize = @intCast(c.BTF_INFO_VLEN(@as(c_int, @bitCast(t.info))));
            const params: [*c]c.btf_param = @ptrFromInt(@intFromPtr(t) + @sizeOf(c.btf_type));

            for (0..vlen) |pi| {
                if (params[pi].name_off == 0) {
                    const name = try std.fmt.allocPrintZ(allocator, "arg{}", .{pi});
                    dbg_print("fix function arg{}'s name to {s}\n", .{ pi, name });
                    params[pi].name_off = try btf_add_str(dst_btf, name);
                }
            }
        } else if (c.btf_is_var(t) and c.btf_var(t)[0].linkage == c.BTF_VAR_GLOBAL_EXTERN and t.name_off > 0) {
            const s = c.btf__str_by_offset(dst_btf, t.name_off);
            try externs_with_btf.put(std.mem.sliceTo(s, 0), @intCast(i));
        }
    }

    // add extern ksyms
    var scn = c.elf_nextscn(elf, null);
    const vmlinux_btf = if (vmlinux_arg) |vmlinux| c.btf__parse(vmlinux, null) else c.btf__load_vmlinux_btf();
    var ksym_ids = std.ArrayList(u32).init(allocator);
    var created_type_ids = std.AutoHashMap(u32, u32).init(allocator); // map from src to dst type id
    defer {
        ksym_ids.deinit();
        created_type_ids.deinit();
    }
    while (scn) |section| : (scn = c.elf_nextscn(elf, scn)) {
        const shdr: *c.Elf64_Shdr = c.elf64_getshdr(section) orelse {
            print("failed to get section header: {}\n", .{std.posix.errno(-1)});
            return error.PARSE;
        };
        if (shdr.sh_type == c.SHT_SYMTAB) {
            const data: *const c.Elf_Data = c.elf_getdata(scn, 0) orelse {
                print("failed to get symbol section data: {}\n", .{std.posix.errno(-1)});
                return error.PARSE;
            };
            const syms: [*c]c.Elf64_Sym = @alignCast(@ptrCast(data.d_buf));

            for (0..shdr.sh_size / shdr.sh_entsize) |i| {
                const sym: c.Elf64_Sym = syms[i];
                if (sym.st_shndx == c.SHN_UNDEF and c.ELF64_ST_BIND(sym.st_info) == c.STB_GLOBAL and c.ELF64_ST_TYPE(sym.st_info) == c.STT_NOTYPE) {
                    const name = c.elf_strptr(elf, stridx, sym.st_name) orelse {
                        print("failed to get function name: {}\n", .{std.posix.errno(-1)});
                        return error.PARSE;
                    };
                    if (!externs_with_btf.contains(std.mem.sliceTo(name, 0))) {
                        try ksym_ids.append(try add_kernel_func_btf(dst_btf, name, vmlinux_btf.?, allocator, &created_type_ids));
                    }
                }
            }
        }
    }
    // Add .ksym section
    if (ksym_ids.items.len > 0) {
        const sec_id = c.btf__add_datasec(dst_btf, ".ksyms", 0);
        if (sec_id < 0) {
            print("failed to create .ksyms BTF section: {}\n", .{std.posix.errno(-1)});
            return error.INTERNAL;
        }
        for (ksym_ids.items) |id| {
            ret = c.btf__add_datasec_var_info(dst_btf, @intCast(id), 0, 0);
            if (ret != 0) {
                print("failed to add to .ksyms BTF section: {}\n", .{std.posix.errno(-1)});
                return error.INTERNAL;
            }
        }
    }
    // Add .kconfig section
    if (externs_with_btf.count() > 0) {
        const sec_id = c.btf__add_datasec(dst_btf, ".kconfig", 0);
        if (sec_id < 0) {
            print("failed to create .kconfig BTF section: {}\n", .{std.posix.errno(-1)});
            return error.INTERNAL;
        }
        var val_it = externs_with_btf.valueIterator();
        while (val_it.next()) |id| {
            ret = c.btf__add_datasec_var_info(dst_btf, @intCast(id.*), 0, @intCast(c.btf__resolve_size(src_btf, id.*)));
            if (ret != 0) {
                print("failed to add to .kconfig BTF section: {}\n", .{std.posix.errno(-1)});
                return error.INTERNAL;
            }
        }
    }

    // deduplication and finalize BTF
    // NOTE: redefine due to the original one has bitfields
    const OPT = extern struct {
        sz: usize = @sizeOf(@This()),
        btf_ext: ?*c.btf_ext = null,
        force_collisions: bool = false,
    };
    ret = c.btf__dedup(dst_btf, @ptrCast(&OPT{}));
    if (ret != 0) {
        print("failed to dedup BTF: {}\n", .{std.posix.errno(-1)});
        return error.INTERNAL;
    }
    buf = c.btf__raw_data(dst_btf, &sz);

    // update dst ELF
    scn = c.elf_nextscn(elf, null); // reset scn
    while (scn) |section| : (scn = c.elf_nextscn(elf, scn)) {
        const shdr: *c.Elf64_Shdr = c.elf64_getshdr(section) orelse {
            print("failed to get section header: {}\n", .{std.posix.errno(-1)});
            return error.PARSE;
        };
        const name = c.elf_strptr(elf, stridx, shdr.sh_name) orelse {
            print("failed to get section name: {}\n", .{std.posix.errno(-1)});
            return error.PARSE;
        };
        if (std.mem.eql(u8, name[0..".BTF".len], ".BTF")) {
            var data: *c.Elf_Data = c.elf_newdata(section) orelse {
                print("failed to create section data: {}\n", .{std.posix.errno(-1)});
                return error.OOM;
            };

            data.d_type = c.ELF_T_BYTE;
            data.d_version = c.EV_CURRENT;
            data.d_buf = @constCast(buf);
            data.d_size = sz;

            break;
        }
    } else {
        print("failed to find BTF section in elf\n", .{});
        return error.PARSE;
    }
}

fn btf_add_str(dst_btf: *c.btf, s: [*c]const u8) !c_uint {
    const off = c.btf__add_str(dst_btf, s);
    if (off < 0) {
        print("failed to add str\n", .{});
        return error.OOM;
    }
    return @intCast(off);
}

fn add_kernel_func_btf(dst_btf: *c.btf, name: [*c]const u8, vmlinux_btf: *const c.btf, allocator: std.mem.Allocator, created_type_ids: *std.AutoHashMap(u32, u32)) !u32 {
    for (1..c.btf__type_cnt(vmlinux_btf)) |i| {
        const t: *const c.btf_type = c.btf__type_by_id(vmlinux_btf, @intCast(i));
        if (c.btf_kind(t) == c.BTF_KIND_FUNC) {
            const func_name = c.btf__name_by_offset(vmlinux_btf, t.name_off);
            if (std.mem.indexOfDiff(u8, std.mem.sliceTo(func_name, 0), std.mem.sliceTo(name, 0))) |_| continue else {
                dbg_print("generate BTF for kernel function: {s}\n", .{name});
                const id = try do_add_btf_types(dst_btf, vmlinux_btf, @intCast(i), allocator, created_type_ids);
                // mark func external linkage
                const func_type: *c.btf_type = @constCast(c.btf__type_by_id(dst_btf, @intCast(id)));
                func_type.info >>= 16;
                func_type.info <<= 16;
                func_type.info |= c.BTF_FUNC_EXTERN;
                return id;
            }
        }
    } else {
        print("failed to find btf for function {s}\n", .{name});
        return error.INVALID;
    }
}

fn do_add_btf_types(dst_btf: *c.btf, vmlinux_btf: *const c.btf, type_id: u32, allocator: std.mem.Allocator, created_type_ids: *std.AutoHashMap(u32, u32)) !u32 {
    if (type_id == 0) return 0;
    if (created_type_ids.get(type_id)) |v| return v;

    const t: *const c.btf_type = c.btf__type_by_id(vmlinux_btf, type_id);
    const new_type_id = c.btf__add_type(dst_btf, vmlinux_btf, t);
    if (new_type_id < 0) {
        print("failed to add type {any}\n", .{t});
        return error.INTERNAL;
    }
    try created_type_ids.putNoClobber(type_id, @intCast(new_type_id));

    //dbg_print("tw; add type: {}, name: {s}, id: {} -> {}\n", .{ c.btf_kind(t), if (t.name_off > 0) c.btf__str_by_offset(vmlinux_btf, t.name_off) else "unknown".ptr, type_id, new_type_id });

    // replace field type
    // we have to run two rounds here, as type memory will be invalidated every time you add a new type
    var type_it: c.btf_field_iter = undefined;
    var ret = c.btf_field_iter_init(&type_it, @constCast(t), c.BTF_FIELD_ITER_IDS);
    if (ret != 0) {
        return @intCast(new_type_id); // not iterable
    }
    var fields_type_ids = std.ArrayList(u32).init(allocator);
    defer fields_type_ids.deinit();
    while (c.btf_field_iter_next(&type_it)) |field_type_id| {
        try fields_type_ids.append(try do_add_btf_types(dst_btf, vmlinux_btf, field_type_id.*, allocator, created_type_ids));
    }
    const new_t: *c.btf_type = @constCast(c.btf__type_by_id(dst_btf, @intCast(new_type_id)));
    ret = c.btf_field_iter_init(&type_it, new_t, c.BTF_FIELD_ITER_IDS);
    std.debug.assert(ret == 0);
    while (c.btf_field_iter_next(&type_it)) |field_type_id| {
        field_type_id.* = fields_type_ids.orderedRemove(0);
    }

    return @intCast(new_type_id);
}
