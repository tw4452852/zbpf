const vmlinux = @import("vmlinux");

category: []const u8,
name: []const u8,

const Self = @This();

pub fn section(comptime self: Self) []const u8 {
    return "tracepoint/" ++ self.category ++ "/" ++ self.name;
}

pub fn Ctx(comptime self: Self) type {
    const struct_name = "trace_event_raw_" ++ self.name;
    return @field(vmlinux, struct_name);
}
