const vmlinux = @import("vmlinux");

/// Category of the tracepoint. This is usually the directory name inside `tracefs/events/`.
category: []const u8,
/// Name of the tracepoint. This is usually the directory name inside `tracefs/events/<category/`.
name: []const u8,

const Self = @This();

/// Return ELF section name for tracepoint used by libbpf.
pub fn section(comptime self: Self) []const u8 {
    return "tracepoint/" ++ self.category ++ "/" ++ self.name;
}

/// Return the argument retriever according to the specified tracepoint's context.
pub fn Ctx(comptime self: Self) type {
    const struct_name = "trace_event_raw_" ++ self.name;
    return @field(vmlinux, struct_name);
}
