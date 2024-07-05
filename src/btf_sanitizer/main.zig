const std = @import("std");
const print = std.debug.print;
pub const c = @cImport({
    @cInclude("btf.h");
    @cInclude("libelf.h");
});

// btf_sanitizer src_obj dst_obj
pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();

    const allocator = arena.allocator();

    var it = std.process.args();
    _ = it.skip(); // skip process name
    const src_obj_path = it.next().?;
    const dst_obj_path = it.next().?;

    try std.fs.copyFileAbsolute(src_obj_path, dst_obj_path, .{});

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

    // sanitize
    _ = c.btf__find_str(dst_btf, ""); // ensure btf is in modifiable/splited state
    for (0..c.btf__type_cnt(dst_btf)) |i| {
        const t: *c.btf_type = @constCast(c.btf__type_by_id(dst_btf, @intCast(i)));

        if (c.btf_is_fwd(t) or c.btf_is_struct(t)) {
            // replace non-alphabet with '_'
            const name: [:0]u8 = @constCast(std.mem.sliceTo(c.btf__name_by_offset(dst_btf, t.name_off), 0));
            for (name) |*ch| {
                if (!std.ascii.isAlphabetic(ch.*)) {
                    ch.* = '_';
                }
            }
        } else if (c.btf_is_ptr(t)) {
            // null pointer type name
            t.name_off = 0;
        } else if (c.btf_is_func_proto(t)) {
            // add function parameter's name with 'argX'
            const vlen: usize = @intCast(c.BTF_INFO_VLEN(@as(c_int, @bitCast(t.info))));
            const params: [*c]c.btf_param = @ptrFromInt(@intFromPtr(t) + @sizeOf(c.btf_type));

            for (0..vlen) |pi| {
                if (params[pi].name_off == 0) {
                    const name = try std.fmt.allocPrintZ(allocator, "arg{}", .{pi});
                    var off = c.btf__find_str(dst_btf, name.ptr);
                    if (off < 0) {
                        off = c.btf__add_str(dst_btf, name.ptr);
                        if (off < 0) {
                            print("failed to add str\n", .{});
                            return error.OOM;
                        }
                    }

                    params[pi].name_off = @intCast(off);
                }
            }
        }
    }
    buf = c.btf__raw_data(dst_btf, &sz);

    // update BTF section in elf
    const elf = c.elf_begin(dst_obj.handle, c.ELF_C_RDWR, null) orelse {
        print("failed to open dst elf: {}\n", .{std.posix.errno(-1)});
        return error.PARSE;
    };
    defer {
        _ = c.elf_update(elf, c.ELF_C_WRITE);
        _ = c.elf_end(elf);
    }

    var stridx: usize = undefined;
    const ret = c.elf_getshdrstrndx(elf, &stridx);
    if (ret != 0) {
        print("failed to get string section idx: {}\n", .{std.posix.errno(-1)});
        return error.PARSE;
    }
    var scn = c.elf_nextscn(elf, null);
    const btf_section_name = ".BTF";
    while (scn) |section| : (scn = c.elf_nextscn(elf, scn)) {
        const shdr: *c.Elf64_Shdr = c.elf64_getshdr(section) orelse {
            print("failed to get section header: {}\n", .{std.posix.errno(-1)});
            return error.PARSE;
        };
        const name = c.elf_strptr(elf, stridx, shdr.sh_name) orelse {
            print("failed to get section name: {}\n", .{std.posix.errno(-1)});
            return error.PARSE;
        };
        if (std.mem.eql(u8, name[0..btf_section_name.len], btf_section_name)) {
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
