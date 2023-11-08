const std = @import("std");
const helpers = std.os.linux.BPF.kern.helpers;
const MapType = std.os.linux.BPF.MapType;
const kernelMapDef = std.os.linux.BPF.kern.MapDef;
const StructField = std.builtin.Type.StructField;
const Declaration = std.builtin.Type.Declaration;
const vmlinux = @import("vmlinux");

pub const MapUpdateType = enum(u64) {
    any = std.os.linux.BPF.ANY,
    noexist = std.os.linux.BPF.NOEXIST,
    exist = std.os.linux.BPF.EXIST,
};

fn Map(
    comptime name: []const u8,
    comptime map_type: MapType,
    comptime Key: type,
    comptime Value: type,
    comptime max_entries: u32,
    comptime map_flags: u32,
) type {
    const fields = [_]StructField{
        .{
            .name = "type",
            .type = ?*[@intFromEnum(map_type)]u8,
            .default_value = null,
            .is_comptime = false,
            .alignment = @alignOf(?*[@intFromEnum(map_type)]u8),
        },
        .{
            .name = "key",
            .type = ?*Key,
            .default_value = null,
            .is_comptime = false,
            .alignment = @alignOf(?*Key),
        },
        .{
            .name = "value",
            .type = ?*Value,
            .default_value = null,
            .is_comptime = false,
            .alignment = @alignOf(?*Value),
        },
    } ++ (if (max_entries > 0) [_]StructField{.{
        .name = "max_entries",
        .type = ?*[max_entries]u8,
        .default_value = null,
        .is_comptime = false,
        .alignment = @alignOf(?*[max_entries]u8),
    }} else [_]StructField{}) ++ (if (map_flags > 0) [_]StructField{.{
        .name = "map_flags",
        .type = ?*[map_flags]u8,
        .default_value = null,
        .is_comptime = false,
        .alignment = @alignOf(?*[map_flags]u8),
    }} else [_]StructField{});

    const Def = @Type(.{
        .Struct = .{
            .layout = .Extern,
            .is_tuple = false,
            .fields = &fields,
            .decls = &[_]Declaration{},
        },
    });
    return struct {
        var def: Def = undefined;

        const Self = @This();

        comptime {
            @export(Self.def, .{ .name = name, .section = ".maps" });
        }

        /// Perform a lookup in *map* for an entry associated to *key*.
        pub fn lookup(_: *const Self, key: Key) ?*const Value {
            return @ptrCast(@alignCast(helpers.map_lookup_elem(@ptrCast(&Self.def), &key)));
        }

        /// Add or update the value of the entry associated to `key` in `map`
        /// with `value`. `update_type` is one of
        ///
        /// `noexist`: The entry for *key* must not exist in the map.
        /// `exist`: The entry for *key* must already exist in the map.
        /// `any`: No condition on the existence of the entry for *key*.
        ///
        /// Flag value `noexist` cannot be used for maps of types
        /// `BPF_MAP_TYPE_ARRAY` or `BPF_MAP_TYPE_PERCPU_ARRAY` (all elements
        /// always exist), the helper would return an error.
        pub fn update(_: *const Self, update_type: MapUpdateType, key: Key, value: Value) !void {
            const rc = helpers.map_update_elem(
                @ptrCast(&Self.def),
                &key,
                &value,
                @intFromEnum(update_type),
            );
            return switch (rc) {
                0 => {},
                else => error.Unknown,
            };
        }

        /// Delete entry with *key* from *map*.
        pub fn delete(_: *const Self, key: Key) !void {
            const rc = helpers.map_delete_elem(@ptrCast(&Self.def), &key);
            return switch (rc) {
                0 => {},
                else => error.Unknown,
            };
        }
    };
}

pub fn HashMap(
    comptime name: []const u8,
    comptime Key: type,
    comptime Value: type,
    comptime max_entries: u32,
    comptime flags: u32,
) type {
    return struct {
        map: Map(name, .hash, Key, Value, max_entries, flags),

        const Self = @This();

        pub fn init() Self {
            return .{ .map = .{} };
        }

        pub fn lookup(self: *const Self, key: Key) ?*const Value {
            return self.map.lookup(key);
        }

        pub fn update(self: *const Self, update_type: MapUpdateType, key: Key, value: Value) !void {
            return self.map.update(update_type, key, value);
        }

        pub fn delete(self: *const Self, key: Key) !void {
            return self.map.delete(key);
        }
    };
}

pub fn ArrayMap(
    comptime name: []const u8,
    comptime Value: type,
    comptime max_entries: u32,
    comptime flags: u32,
) type {
    return struct {
        map: Map(name, .array, u32, Value, max_entries, flags),

        const Self = @This();

        pub fn init() Self {
            return .{ .map = .{} };
        }

        pub fn lookup(self: *const Self, key: u32) ?*const Value {
            return self.map.lookup(key);
        }

        pub fn update(self: *const Self, update_type: MapUpdateType, key: u32, value: Value) !void {
            return self.map.update(update_type, key, value);
        }
    };
}

pub fn PerfEventArray(
    comptime name: []const u8,
    comptime max_entries: u32,
    comptime array_flags: u32,
) type {
    return struct {
        map: Map(name, .perf_event_array, u32, u32, max_entries, array_flags),

        const Self = @This();

        pub fn init() Self {
            return .{ .map = .{} };
        }

        pub fn event_output(self: *const Self, ctx: anytype, index: ?u64, data: []const u8) !void {
            const rc = helpers.perf_event_output(ctx, @ptrCast(&@TypeOf(self.map).def), if (index) |i| i else vmlinux.BPF_F_CURRENT_CPU, @constCast(data.ptr), data.len);
            return switch (rc) {
                0 => {},
                else => error.Unknown,
            };
        }
    };
}

pub const RingBufNotify = enum {
    auto,
    force_notify,
    not_notify,
};

pub fn RingBuffer(
    comptime name: []const u8,
    comptime number_of_pages: u32,
    comptime flags: u32,
) type {
    return struct {
        map: Map(name, .ringbuf, void, void, number_of_pages * 4096, flags),

        const Self = @This();

        pub fn init() Self {
            return .{ .map = .{} };
        }

        pub fn event_output(self: *const Self, data: []const u8, notify: RingBufNotify) !void {
            const rc = helpers.ringbuf_output(&@TypeOf(self.map).def, @constCast(data.ptr), data.len, switch (notify) {
                .auto => 0,
                .force_notify => vmlinux.BPF_RB_FORCE_WAKEUP,
                .not_notify => vmlinux.BPF_RB_NO_WAKEUP,
            });
            return switch (rc) {
                0 => {},
                else => error.Unknown,
            };
        }

        pub fn reserve(self: *const Self, comptime T: type) !struct {
            data_ptr: *T,

            pub fn commit(s: *const @This()) void {
                helpers.ringbuf_submit(s.data_ptr, 0);
            }
        } {
            if (helpers.ringbuf_reserve(&@TypeOf(self.map).def, @sizeOf(T), 0)) |ptr| return .{
                .data_ptr = @alignCast(@ptrCast(ptr)),
            } else return error.Unknown;
        }
    };
}
