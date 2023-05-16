const vmlinux = @import("vmlinux");
const std = @import("std");
const StructField = std.builtin.Type.StructField;

pub fn Ctx(comptime name: []const u8) type {
    const f = @typeInfo(@TypeOf(@field(vmlinux, name)));
    comptime var fields: []const StructField = &.{};

    for (0.., f.Fn.params) |i, arg| {
        fields = fields ++ [_]StructField{
            .{
                .name = std.fmt.comptimePrint("arg{}", .{i}),
                .type = arg.type.?,
                .default_value = null,
                .is_comptime = false,
                .alignment = @sizeOf(u64),
            },
        };
    }

    fields = fields ++ [_]StructField{
        .{
            .name = "ret",
            .type = f.Fn.return_type.?,
            .default_value = null,
            .is_comptime = false,
            .alignment = @sizeOf(u64),
        },
    };

    return @Type(.{
        .Struct = .{
            .layout = .Extern,
            .is_tuple = false,
            .fields = fields,
            .decls = &.{},
        },
    });
}
