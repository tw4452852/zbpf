const std = @import("std");

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();

    const gpa = arena.allocator();

    const input = try std.io.getStdIn().reader().readAllAlloc(gpa, std.math.maxInt(u32));
    const tree = try std.json.parseFromSlice(std.json.Value, gpa, input, .{});
    const syscalls = tree.value.object.get("syscalls").?;

    const w = std.fs.File.stdout();
    for (syscalls.array.items) |syscall| {
        const args = syscall.object.get("signature").?.array.items;
        try w.print("pub const {s} = fn (", .{syscall.object.get("origname").?.string});
        defer w.writeAll(") c_long;\n") catch unreachable;

        for (args) |arg| {
            const arg_s = arg.string;
            const space = std.mem.lastIndexOfScalar(u8, arg_s, ' ').?;
            var ptr_opt: ?usize = null;
            var name = space + 1;
            while (arg_s[name] == '*') {
                if (ptr_opt == null) ptr_opt = name;
                name += 1;
            }

            var typ_begin: usize = 0;
            while (std.mem.startsWith(u8, arg_s[typ_begin..], "const ")) typ_begin += "const ".len;
            while (std.mem.startsWith(u8, arg_s[typ_begin..], "struct ")) typ_begin += "struct ".len;
            while (std.mem.startsWith(u8, arg_s[typ_begin..], "enum ")) typ_begin += "enum ".len;
            while (std.mem.startsWith(u8, arg_s[typ_begin..], "union ")) typ_begin += "union ".len;

            const const_ptr_suffix: ?usize = std.mem.lastIndexOf(u8, arg_s[typ_begin..space], " *const");
            const typ_s = try gpa.dupe(u8, arg_s[typ_begin..space][0..if (const_ptr_suffix) |i| i else space - typ_begin]);
            std.mem.replaceScalar(u8, typ_s, ' ', '_');
            const zig_typ_s = if (std.mem.eql(u8, typ_s, "unsigned_long"))
                "c_ulong"
            else if (std.mem.eql(u8, typ_s, "long"))
                "long_int"
            else if (std.mem.eql(u8, typ_s, "unsigned"))
                "unsigned_int"
            else
                try std.fmt.allocPrint(gpa, "Kernel.{s}", .{typ_s});

            try w.print("{s}: {s}{s}{s}, ", .{ arg_s[name..], if (ptr_opt) |ptr| arg_s[ptr..name] else "", if (const_ptr_suffix != null) "*" else "", zig_typ_s });
        }
    }
}
