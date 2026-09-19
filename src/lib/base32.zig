const dictionary = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

const std = @import("std");
const testing = std.testing;
const Allocator = std.mem.Allocator;

pub fn decode(allocator: Allocator, input: []const u8) ![]u8 {
    const maybe_padding_index = std.mem.indexOf(u8, input, "=");
    var data_length = input.len;
    var padding_length: usize = 0;
    if (maybe_padding_index) |padding_index| {
        data_length = padding_index;
        for (input[padding_index..]) |i| {
            if (i != '=') return error.InvalidEncoding;
        }
        padding_length = input.len - padding_index;
    }

    const expected_padding: usize = switch (data_length % 8) {
        0 => 0,
        2 => 6,
        4 => 4,
        5 => 3,
        7 => 1,
        else => return error.InvalidEncoding,
    };

    if (padding_length > 0 and padding_length != expected_padding) {
        return error.InvalidEncoding;
    }

    const output_length = (data_length / 8) * 5 + ((data_length % 8) * 5) / 8;
    const output = try allocator.alloc(u8, output_length);
    errdefer allocator.free(output);

    var buffer: u16 = 0;
    var bits: u4 = 0;
    var written: usize = 0;

    for (input[0..data_length]) |character| {
        const value: u8 = switch (character) {
            'A'...'Z' => character - 'A',
            'a'...'z' => character - 'a',
            '2'...'7' => character - '2' + 26,
            else => return error.InvalidEncoding,
        };
        buffer = (buffer << 5) | value;
        bits += 5;

        if (bits >= 8) {
            bits -= 8;
            output[written] = @intCast(buffer >> bits);
            written += 1;
            buffer = buffer & ((@as(u16, 1) << bits) - 1);
        }
    }

    if (buffer != 0) return error.InvalidEncoding;

    return output;
}

fn expectDecoded(input: []const u8, expected: []const u8) !void {
    errdefer std.debug.print("\nBase32 fixture: {s}\n", .{input});
    const actual = try decode(testing.allocator, input);
    defer testing.allocator.free(actual);
    try testing.expectEqualSlices(u8, expected, actual);
}

// Free unexpected successes too, so a failed assertion doesn't cause a leak.
fn expectInvalid(input: []const u8) !void {
    errdefer std.debug.print("\nInvalid Base32 fixture: {s}\n", .{input});
    const result = decode(testing.allocator, input);
    if (result) |bytes| {
        testing.allocator.free(bytes);
        return error.TestUnexpectedSuccess;
    } else |err| {
        try testing.expectEqual(error.InvalidEncoding, err);
    }
}

test "Base32 first byte" {
    try expectDecoded("MY", "f");
}

test "Base32 RFC 4648 vectors with and without padding" {
    const cases = [_]struct { encoded: []const u8, decoded: []const u8 }{
        .{ .encoded = "", .decoded = "" },
        .{ .encoded = "MY======", .decoded = "f" },
        .{ .encoded = "MZXQ====", .decoded = "fo" },
        .{ .encoded = "MZXW6===", .decoded = "foo" },
        .{ .encoded = "MZXW6YQ=", .decoded = "foob" },
        .{ .encoded = "MZXW6YTB", .decoded = "fooba" },
        .{ .encoded = "MZXW6YTBOI======", .decoded = "foobar" },
    };

    for (cases) |case| {
        try expectDecoded(case.encoded, case.decoded);
        const end = std.mem.indexOfScalar(u8, case.encoded, '=') orelse case.encoded.len;
        try expectDecoded(case.encoded[0..end], case.decoded);
    }
}

test "Base32 accepts lowercase and mixed case" {
    try expectDecoded("mzxw6ytboi======", "foobar");
    try expectDecoded("MzXw6yTbOi", "foobar");
}

test "Base32 returns binary bytes including zero and high bits" {
    try expectDecoded("AA======", &.{0x00});
    try expectDecoded("74======", &.{0xff});
    try expectDecoded("77777777", &.{ 0xff, 0xff, 0xff, 0xff, 0xff });
    try expectDecoded("JBSWY3DPEHPK3PXP", "Hello!\xde\xad\xbe\xef");
}

test "Base32 rejects invalid characters" {
    for ([_][]const u8{
        "M0",          "M1",           "M8", "M9", "M!", "M ", "M\n", "M\t", "M\x00", "M\xff",
        " MZXW6YTBOI", "MZXW6YTBOI\n",
    }) |input| {
        try expectInvalid(input);
    }
}

test "Base32 rejects impossible data lengths" {
    for ([_][]const u8{ "A", "AAA", "AAAAAA", "AAAAAAAAA" }) |input| {
        try expectInvalid(input);
    }
}

test "Base32 rejects malformed padding" {
    for ([_][]const u8{
        "=",        "========",  "MY=",              "MY=====",  "MY=======",
        "M=Y=====", "MY======A", "MZXW6YTB========", "A=======",
    }) |input| {
        try expectInvalid(input);
    }
}

test "Base32 rejects nonzero unused bits" {
    // One invalid final symbol for each possible partial-byte ending.
    for ([_][]const u8{
        "MZ",    "MZ======", "MZXR",    "MZXR====",
        "MZXW7", "MZXW7===", "MZXW6YR", "MZXW6YR=",
    }) |input| {
        try expectInvalid(input);
    }
}

// Keep OutOfMemory in the helper error set even while decode is a stub.
fn allocationCase(allocator: Allocator) anyerror!void {
    const bytes = try decode(allocator, "MZXW6YTBOI======");
    defer allocator.free(bytes);
    try testing.expectEqualSlices(u8, "foobar", bytes);
}

test "Base32 handles allocation failure" {
    try testing.checkAllAllocationFailures(testing.allocator, allocationCase, .{});
}
