const std = @import("std");
const print = std.debug.print;
const c = @cImport({
    @cInclude("btf.h");
});
const gpa = std.testing.allocator;
const vmlinux = @import("vmlinux");
const build_options = @import("@build_options");

test "vmlinux_compile" {
    @setEvalBranchQuota(1000000);
    std.testing.refAllDeclsRecursive(vmlinux);
}

test "vmlinux_check_offset_one" {
    try test_offset("task_struct");
}

fn test_offset(comptime struct_name_filter: ?[]const u8) !void {
    @setEvalBranchQuota(1000000);

    const btf = if (build_options.vmlinux_bin_path.len > 0) c.btf__parse(build_options.vmlinux_bin_path, null) else c.btf__load_vmlinux_btf();
    if (btf == null) {
        print("failed to get BTF: {}\n", .{std.posix.errno(-1)});
        return error.PARSE;
    }

    const sizes, const offsets = blk: {
        comptime var size_array: []const struct { []const u8, usize } = &.{};
        comptime var offset_array: []const struct { []const u8, usize } = &.{};
        const decls = @typeInfo(vmlinux).@"struct".decls;

        inline for (decls) |decl| {
            const t = @field(vmlinux, decl.name);
            const ti = @typeInfo(t);
            switch (ti) {
                .@"struct" => |info| {
                    comptime if (struct_name_filter == null or std.mem.eql(u8, struct_name_filter.?, decl.name)) {
                        size_array = size_array ++ .{.{ decl.name, @sizeOf(t) }};
                        for (info.fields) |field| {
                            offset_array = offset_array ++ .{.{ decl.name ++ "/" ++ field.name, @bitOffsetOf(t, field.name) }};
                        }
                    };
                },
                else => {},
            }
        }

        break :blk .{ std.StaticStringMap(usize).initComptime(size_array), std.StaticStringMap(usize).initComptime(offset_array) };
    };

    // Check structure size and non-bitfield offsets are consistent with btf
    for (1..c.btf__type_cnt(btf)) |i| {
        const t: *const c.btf_type = c.btf__type_by_id(btf, @intCast(i));
        if (c.btf_kind(t) == c.BTF_KIND_STRUCT) {
            const struct_sz = t.unnamed_0.size;
            const m: [*c]const c.struct_btf_member = c.btf_members(t);
            const vlen: u16 = c.btf_vlen(t);
            const btf_name: [:0]const u8 = std.mem.sliceTo(c.btf__name_by_offset(btf, t.name_off), 0);
            const struct_name = if (btf_name.len != 0)
                try gpa.dupe(u8, btf_name)
            else
                try std.fmt.allocPrint(gpa, "struct_{d}", .{i});
            defer gpa.free(struct_name);
            if (struct_name_filter == null or std.mem.eql(u8, struct_name_filter.?, struct_name)) {
                try std.testing.expectEqual(struct_sz, sizes.get(struct_name).?);
                for (0..vlen) |vi| {
                    const m_sz = c.btf_member_bitfield_size(t, @intCast(vi));
                    const m_off = c.btf_member_bit_offset(t, @intCast(vi));

                    // TODO: skip bitfield right now
                    if (m_sz != 0) continue;

                    const field_name = if (m[vi].name_off != 0)
                        try gpa.dupe(u8, std.mem.sliceTo(c.btf__name_by_offset(btf, m[vi].name_off), 0))
                    else
                        try std.fmt.allocPrint(gpa, "field{}", .{vi});
                    defer gpa.free(field_name);
                    const key = try std.fmt.allocPrint(gpa, "{s}/{s}", .{ struct_name, field_name });
                    defer gpa.free(key);

                    try std.testing.expectEqual(m_off, offsets.get(key).?);
                }
            }
        }
    }
}
