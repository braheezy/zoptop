const std = @import("std");

pub fn SecretInput(comptime capacity: usize) type {
    return struct {
        const Self = @This();

        bytes: [capacity]u8 = @splat(0),
        len: usize = 0,

        pub fn append(self: *Self, text: []const u8) !void {
            if (!std.unicode.utf8ValidateSlice(text)) return error.InvalidText;
            for (text) |byte| {
                if (byte < 0x20 or byte == 0x7f)
                    return error.InvalidText;
            }
            if (text.len > capacity - self.len) return error.InputTooLong;
            if (text.len == 0) return;

            @memcpy(self.bytes[self.len .. self.len + text.len], text);
            self.len += text.len;
        }

        pub fn backspace(self: *Self) void {
            if (self.len == 0) return;

            var start = self.len - 1;

            // UTF-8 continuation bytes start with the binary bits 10.
            while (start > 0 and (self.bytes[start] & 0xc0) == 0x80) {
                start -= 1;
            }

            std.crypto.secureZero(u8, self.bytes[start..self.len]);
            self.len = start;
        }

        pub fn clear(self: *Self) void {
            std.crypto.secureZero(u8, &self.bytes);
            self.len = 0;
        }

        pub fn slice(self: *const Self) []const u8 {
            return self.bytes[0..self.len];
        }
    };
}

const testing = std.testing;

test "secret input appends ASCII and UTF-8 without changing spaces" {
    var input: SecretInput(32) = .{};
    defer input.clear();
    try input.append("hello ");
    try input.append("é🔑 ");
    try testing.expectEqualStrings("hello é🔑 ", input.slice());
    try testing.expectEqual(@as(usize, "hello é🔑 ".len), input.len);
    try input.append("");
    try testing.expectEqualStrings("hello é🔑 ", input.slice());
}

test "secret input accepts an exactly full buffer" {
    var input: SecretInput(3) = .{};
    defer input.clear();
    try input.append("aé"); // One ASCII byte and two UTF-8 bytes.
    try testing.expectEqualStrings("aé", input.slice());
    try testing.expectEqual(@as(usize, 3), input.len);
    try input.append("");
    try testing.expectEqualStrings("aé", input.slice());
}

test "secret input rejects every ASCII control and DEL" {
    for (0..128) |value| {
        if (value >= 0x20 and value != 0x7f) continue;
        errdefer std.debug.print("control byte: 0x{x}\n", .{value});
        var input: SecretInput(8) = .{};
        const text = [_]u8{ 'a', @intCast(value), 'b' };
        try testing.expectError(error.InvalidText, input.append(&text));
        try testing.expectEqual(@as(usize, 0), input.len);
        try testing.expectEqualSlices(u8, &([_]u8{0} ** 8), &input.bytes);
    }
}

test "secret input rejects invalid UTF-8 without copying a prefix" {
    for ([_][]const u8{ "a\xff", "a\xc3", "a\x80", "\xc0\xaf", "\xed\xa0\x80", "\xf4\x90\x80\x80" }) |text| {
        var input: SecretInput(16) = .{};
        try testing.expectError(error.InvalidText, input.append(text));
        try testing.expectEqualStrings("", input.slice());
        try testing.expectEqualSlices(u8, &([_]u8{0} ** 16), &input.bytes);
    }
}

test "secret input overflow leaves existing text and storage unchanged" {
    var input: SecretInput(8) = .{};
    defer input.clear();
    try input.append("ok");
    const before = input.bytes;
    try testing.expectError(error.InputTooLong, input.append("1234567"));
    try testing.expectEqualStrings("ok", input.slice());
    try testing.expectEqualSlices(u8, &before, &input.bytes);
    try testing.expectError(error.InvalidText, input.append("a\nb"));
    try testing.expectEqualStrings("ok", input.slice());
    try testing.expectEqualSlices(u8, &before, &input.bytes);
}

test "secret input backspace on empty is harmless" {
    var input: SecretInput(8) = .{};
    input.backspace();
    try testing.expectEqual(@as(usize, 0), input.len);
    try testing.expectEqualSlices(u8, &([_]u8{0} ** 8), &input.bytes);
}

test "secret input backspace removes and wipes complete codepoints" {
    // Set up the buffer directly so this test can run before append works.
    var input: SecretInput(16) = .{};
    defer input.clear();
    const text = "aé🔑";
    @memcpy(input.bytes[0..text.len], text);
    input.len = text.len;
    input.backspace();
    try testing.expectEqualStrings("aé", input.slice());
    try testing.expectEqualSlices(u8, &([_]u8{0} ** 4), input.bytes[3..7]);
    input.backspace();
    try testing.expectEqualStrings("a", input.slice());
    try testing.expectEqualSlices(u8, &([_]u8{0} ** 2), input.bytes[1..3]);
    input.backspace();
    input.backspace();
    try testing.expectEqualStrings("", input.slice());
    try testing.expectEqualSlices(u8, &([_]u8{0} ** 16), &input.bytes);
}

test "secret input clear wipes the entire backing array" {
    var input: SecretInput(16) = .{};
    // Include bytes beyond len: clear promises to wipe the whole array.
    @memset(&input.bytes, 'x');
    input.len = 3;
    input.clear();
    try testing.expectEqual(@as(usize, 0), input.len);
    try testing.expectEqualStrings("", input.slice());
    try testing.expectEqualSlices(u8, &([_]u8{0} ** 16), &input.bytes);
    input.clear();
    try testing.expectEqual(@as(usize, 0), input.len);
}
