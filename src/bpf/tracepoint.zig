const std = @import("std");
const builtin = std.builtin;
const mem = std.mem;
const StructField = builtin.Type.StructField;
const Declaration = builtin.Type.Declaration;

category: []const u8,
name: []const u8,

const Self = @This();

fn prepend(comptime self: Self, comptime prefix: []const u8) []const u8 {
    return prefix ++ self.category ++ "/" ++ self.name;
}

fn tplist(comptime self: Self) []const u8 {
    return self.prepend("tracefs/events/") ++ "/format";
}

fn get_value(comptime T: type, comptime line: []const u8, key_name: []const u8) T {
    const key = key_name ++ ":";
    const begin = key.len + (mem.indexOf(u8, line, key) orelse @compileError("Key not found"));
    const end = mem.indexOf(u8, line[begin..], ";") orelse @compileError("No semicolon found");

    return if (T == []const u8)
        line[begin .. begin + end]
    else
        std.fmt.parseInt(T, line[begin .. begin + end], 10) catch unreachable;
}

pub fn section(comptime self: Self) []const u8 {
    return self.prepend("tracepoint/");
}

pub fn Ctx(comptime self: Self) type {
    const file = @embedFile(self.tplist());

    @setEvalBranchQuota(200000);
    const label = "format:\n";
    const begin = label.len + (mem.indexOf(u8, file, label) orelse @compileError("No format label"));

    comptime var fields: []const StructField = &[0]StructField{};
    comptime var expected_offset = 0;

    comptime var it = mem.tokenize(u8, file[begin..], "\n");
    while (it.next()) |line| {
        if (!mem.startsWith(u8, line, "\t")) {
            break;
        }

        const field = get_value([]const u8, line, "field");
        const left_bracket = mem.indexOf(u8, field, "[");
        const name = field[(mem.lastIndexOf(u8, field, " ") orelse @compileError("no spaces")) + 1 .. if (left_bracket) |l| l else field.len];
        const offset = get_value(usize, line, "offset");
        const size = get_value(usize, line, "size");

        if (offset < expected_offset) {
            @compileError("non-monotonic field offset");
        } else if (offset > expected_offset) {
            // check for alignment
            if (offset % size != 0) {
                @compileError("misalignment");
            } else if (offset - expected_offset > size) {
                @compileError("TODO: padding");
            }

            @compileError("wrong offset");
        }

        const field_type = if (left_bracket != null) @Type(.{
            .Array = .{
                .len = size,
                .child = u8,
                .sentinel = null,
            },
        }) else std.meta.Int(
            if (get_value(u8, line, "signed") > 0) .signed else .unsigned,
            size * @bitSizeOf(u8),
        );
        const f = StructField{
            .name = name,
            .type = field_type,
            .default_value = null,
            .is_comptime = false,
            .alignment = 1,
        };
        fields = fields ++ &[_]StructField{f};

        expected_offset += size;
    }

    return @Type(.{
        .Struct = .{
            .layout = .Extern,
            .is_tuple = false,
            .fields = fields,
            .decls = &[_]Declaration{},
        },
    });
}
