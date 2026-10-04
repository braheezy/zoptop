const std = @import("std");

pub fn format(value: u32, digits: u8, output: []u8) ![]const u8 {
    if (digits != 6 and digits != 8) return error.InvalidDigits;
    if (digits > output.len) return error.BufferTooSmall;

    var buf = output[0..digits];

    for (0..digits) |i| {
        buf[i] = '0';
    }

    var current = value;
    var n = digits;
    while (current > 0) {
        if (n == 0) return error.CodeTooLarge;
        n = n - 1;
        buf[n] = std.fmt.digitToChar(@intCast(current % 10), .lower);
        current /= 10;
    }
    return buf;
}

const testing = std.testing;

test "format pads codes with leading zeros" {
    const cases = [_]struct { value: u32, digits: u8, expected: []const u8 }{
        .{ .value = 0, .digits = 6, .expected = "000000" },
        .{ .value = 1, .digits = 6, .expected = "000001" },
        .{ .value = 123, .digits = 6, .expected = "000123" },
        .{ .value = 287082, .digits = 6, .expected = "287082" },
        .{ .value = 999999, .digits = 6, .expected = "999999" },
        .{ .value = 0, .digits = 8, .expected = "00000000" },
        .{ .value = 7081804, .digits = 8, .expected = "07081804" },
        .{ .value = 99999999, .digits = 8, .expected = "99999999" },
    };
    for (cases) |case| {
        errdefer @import("std").debug.print("value={d}, digits={d}\n", .{ case.value, case.digits });
        var buffer: [8]u8 = undefined;
        const actual = try format(case.value, case.digits, &buffer);
        try testing.expectEqualStrings(case.expected, actual);
    }
}

test "format returns the used part of the caller's buffer" {
    var buffer = @as([10]u8, @splat('!'));
    const actual = try format(42, 6, &buffer);
    try testing.expectEqualStrings("000042", actual);
    try testing.expect(actual.ptr == buffer[0..].ptr);
    try testing.expectEqualStrings("!!!!", buffer[6..]);
}

test "format accepts an exactly sized buffer" {
    var buffer: [6]u8 = undefined;
    try testing.expectEqualStrings("000042", try format(42, 6, &buffer));
}

test "format rejects unsupported digit counts" {
    var buffer: [8]u8 = undefined;
    for ([_]u8{ 0, 1, 5, 7, 9, 255 }) |digits| {
        try testing.expectError(error.InvalidDigits, format(0, digits, &buffer));
    }
}

test "format rejects buffers that are too short" {
    var buffer: [8]u8 = undefined;
    try testing.expectError(error.BufferTooSmall, format(1, 6, buffer[0..0]));
    try testing.expectError(error.BufferTooSmall, format(1, 6, buffer[0..5]));
    try testing.expectError(error.BufferTooSmall, format(1, 8, buffer[0..7]));
}

test "format rejects numbers that do not fit" {
    var buffer: [8]u8 = undefined;
    try testing.expectError(error.CodeTooLarge, format(1_000_000, 6, &buffer));
    try testing.expectError(error.CodeTooLarge, format(100_000_000, 8, &buffer));
    try testing.expectError(error.CodeTooLarge, format(0xffffffff, 8, &buffer));
}
