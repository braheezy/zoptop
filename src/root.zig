pub const hotp = @import("hotp.zig");
pub const Totp = @import("totp.zig").Totp;
pub const otpauth = @import("otpauth.zig");
pub const Account = @import("Account.zig");
const codes = @import("codes.zig");
const Algorithm = @import("algorithm.zig").Algorithm;

const std = @import("std");
const testing = std.testing;

test {
    @import("std").testing.refAllDecls(@This());
}

const uri1 = "otpauth://totp/Example:alice?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=8";
const uri256 = "otpauth://totp/Example:bob?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA&algorithm=SHA256&digits=8";
const uri512 = "otpauth://totp/Example:carol?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA&algorithm=SHA512&digits=8";

fn expectCode(account: Account, timestamp: i64, expected: []const u8) !void {
    var buffer: [8]u8 = undefined;
    const number = try account.generator().generate(timestamp);
    const text = try codes.format(number, account.digits, &buffer);
    try testing.expectEqualStrings(expected, text);
}

test "core: all RFC 6238 vectors" {
    const key20 = "12345678901234567890";
    const key32 = "12345678901234567890123456789012";
    const key64 = "1234567890123456789012345678901234567890123456789012345678901234";
    const algorithms = [_]Algorithm{ .sha1, .sha256, .sha512 };
    const keys = [_][]const u8{ key20, key32, key64 };
    const cases = [_]struct { time: i64, expected: [3]u32 }{
        .{ .time = 59, .expected = .{ 94287082, 46119246, 90693936 } },
        .{ .time = 1111111109, .expected = .{ 7081804, 68084774, 25091201 } },
        .{ .time = 1111111111, .expected = .{ 14050471, 67062674, 99943326 } },
        .{ .time = 1234567890, .expected = .{ 89005924, 91819424, 93441116 } },
        .{ .time = 2000000000, .expected = .{ 69279037, 90698825, 38618901 } },
        .{ .time = 20000000000, .expected = .{ 65353130, 77737706, 47863826 } },
    };
    for (cases) |case| {
        for (algorithms, keys, 0..) |algorithm, key, i| {
            errdefer std.debug.print("time={d}, algorithm={s}\n", .{ case.time, @tagName(algorithm) });
            const generator = Totp{ .secret = key, .digits = 8, .algorithm = algorithm };
            try testing.expectEqual(case.expected[i], try generator.generate(case.time));
        }
    }
}

test "core: formatting and time remaining" {
    var buffer: [8]u8 = undefined;
    try testing.expectEqualStrings("000123", try codes.format(123, 6, &buffer));
    try testing.expectEqualStrings("00000000", try codes.format(0, 8, &buffer));
    try testing.expectEqualStrings("07081804", try codes.format(7081804, 8, &buffer));
    try testing.expectError(error.InvalidDigits, codes.format(1, 7, &buffer));
    try testing.expectError(error.CodeTooLarge, codes.format(1_000_000, 6, &buffer));
    try testing.expectError(error.BufferTooSmall, codes.format(1, 8, buffer[0..6]));
    const generator = Totp{ .secret = "key", .period = 60 };
    try testing.expectEqual(@as(u32, 60), try generator.remaining(0));
    try testing.expectEqual(@as(u32, 1), try generator.remaining(59));
    try testing.expectEqual(@as(u32, 60), try generator.remaining(60));
    try testing.expectError(error.InvalidTimestamp, generator.remaining(-1));
    const bad = Totp{ .secret = "key", .period = 0 };
    try testing.expectError(error.InvalidPeriod, bad.remaining(0));
}

test "core: URI settings reach all three algorithms" {
    const uris = [_][]const u8{ uri1, uri256, uri512 };
    const expected = [_][]const u8{ "94287082", "46119246", "90693936" };
    for (uris, expected) |uri, code| {
        const account = try otpauth.parse(testing.allocator, uri);
        defer account.deinit(testing.allocator);
        try expectCode(account, 59, code);
    }
}
