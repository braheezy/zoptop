pub const Kind = enum { info, err };

pub const Status = struct {
    bytes: [256]u8 = @splat(0),
    used: usize = 0,
    kind: Kind = .info,

    pub fn set(self: *Status, text: []const u8, kind: Kind) !void {
        if (text.len > 256) return error.MessageTooLong;
        @memcpy(self.bytes[0..text.len], text);
        self.used = text.len;
        self.kind = kind;
    }
    pub fn clear(self: *Status) void {
        self.used = 0;
    }
    pub fn slice(self: *const Status) []const u8 {
        return self.bytes[0..self.used];
    }
};

const testing = @import("std").testing;

test "status starts empty" {
    const status: Status = .{};
    try testing.expectEqual(@as(usize, 0), status.used);
    try testing.expectEqual(Kind.info, status.kind);
    try testing.expectEqualStrings("", status.slice());
    try testing.expectEqualSlices(u8, &([_]u8{0} ** 256), &status.bytes);
}

test "status replaces the previous message and kind" {
    var status: Status = .{};
    try status.set("Could not open the vault", .err);
    try testing.expectEqualStrings("Could not open the vault", status.slice());
    try testing.expectEqual(Kind.err, status.kind);
    try status.set("Saved", .info);
    try testing.expectEqualStrings("Saved", status.slice());
    try testing.expectEqual(@as(usize, 5), status.used);
    try testing.expectEqual(Kind.info, status.kind);
}

test "status owns a copy of the message" {
    var status: Status = .{};
    var message = [_]u8{ 'S', 'a', 'v', 'e', 'd' };
    try status.set(&message, .info);
    @memset(&message, 'x');
    try testing.expectEqualStrings("Saved", status.slice());
    try testing.expect(status.slice().ptr == status.bytes[0..].ptr);
}

test "status accepts exactly 256 bytes and an empty message" {
    var status: Status = .{};
    const message = [_]u8{'x'} ** 256;
    try status.set(&message, .err);
    try testing.expectEqual(@as(usize, 256), status.used);
    try testing.expectEqualStrings(&message, status.slice());
    try testing.expectEqual(Kind.err, status.kind);
    try status.set("", .info);
    try testing.expectEqual(@as(usize, 0), status.used);
    try testing.expectEqualStrings("", status.slice());
    try testing.expectEqual(Kind.info, status.kind);
}

test "status rejects an oversized message without changing anything" {
    var status: Status = .{};
    try status.set("Keep this error", .err);
    const before = status;
    const too_long = [_]u8{'x'} ** 257;
    try testing.expectError(error.MessageTooLong, status.set(&too_long, .info));
    try testing.expectEqualStrings("Keep this error", status.slice());
    try testing.expectEqual(before.used, status.used);
    try testing.expectEqual(before.kind, status.kind);
    try testing.expectEqualSlices(u8, &before.bytes, &status.bytes);
}

test "status clear empties the message and allows reuse" {
    var status: Status = .{};
    try status.set("An error", .err);
    status.clear();
    try testing.expectEqual(@as(usize, 0), status.used);
    try testing.expectEqualStrings("", status.slice());
    status.clear();
    try testing.expectEqualStrings("", status.slice());
    try status.set("Ready", .info);
    try testing.expectEqualStrings("Ready", status.slice());
    try testing.expectEqual(Kind.info, status.kind);
}
