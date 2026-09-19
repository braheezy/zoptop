const std = @import("std");
const testing = std.testing;
const hotp = @import("hotp.zig");
const Algorithm = @import("algorithm.zig").Algorithm;

pub const Totp = struct {
    secret: []const u8,
    digits: u8 = 6,
    period: u32 = 30,
    algorithm: Algorithm = .sha1,

    pub fn generate(self: Totp, timestamp: i64) !u32 {
        if (self.period == 0) return error.InvalidPeriod;
        if (timestamp < 0) return error.InvalidTimestamp;

        const counter: u64 = @intCast(@divFloor(timestamp, self.period));
        const code = try hotp.generateWithAlgorithm(self.secret, counter, self.digits, self.algorithm);
        return code;
    }

    pub fn remaining(self: Totp, timestamp: i64) !u32 {
        if (self.period == 0) return error.InvalidPeriod;
        if (timestamp < 0) return error.InvalidTimestamp;

        return self.period - @as(u32, @intCast(@mod(timestamp, self.period)));
    }
};

const test_secret = "12345678901234567890";

fn expectCode(generator: Totp, timestamp: i64, expected: u32) !void {
    const actual = try generator.generate(timestamp);
    errdefer std.debug.print("\nTOTP timestamp: {d}\n", .{timestamp});
    try testing.expectEqual(expected, actual);
}

test "TOTP RFC 6238 SHA1 vectors" {
    const generator = Totp{ .secret = test_secret, .digits = 8 };
    const cases = [_]struct { timestamp: i64, code: u32 }{
        .{ .timestamp = 59, .code = 94287082 },
        .{ .timestamp = 1111111109, .code = 7081804 }, // 07081804
        .{ .timestamp = 1111111111, .code = 14050471 },
        .{ .timestamp = 1234567890, .code = 89005924 },
        .{ .timestamp = 2000000000, .code = 69279037 },
        .{ .timestamp = 20000000000, .code = 65353130 },
    };

    for (cases) |case| {
        try expectCode(generator, case.timestamp, case.code);
    }
}

test "TOTP defaults and window boundaries" {
    const generator = Totp{ .secret = test_secret };
    const cases = [_]struct { timestamp: i64, code: u32 }{
        .{ .timestamp = 0, .code = 755224 },
        .{ .timestamp = 29, .code = 755224 },
        .{ .timestamp = 30, .code = 287082 },
        .{ .timestamp = 59, .code = 287082 },
        .{ .timestamp = 60, .code = 359152 },
    };

    for (cases) |case| {
        try expectCode(generator, case.timestamp, case.code);
    }
}

test "TOTP supports a custom period" {
    const generator = Totp{ .secret = test_secret, .period = 60 };
    try expectCode(generator, 59, 755224);
    try expectCode(generator, 60, 287082);
    try expectCode(generator, 119, 287082);
    try expectCode(generator, 120, 359152);
}

test "TOTP rejects zero periods and negative timestamps" {
    const bad_period = Totp{ .secret = test_secret, .period = 0 };
    try testing.expectError(error.InvalidPeriod, bad_period.generate(59));

    const generator = Totp{ .secret = test_secret };
    try testing.expectError(error.InvalidTimestamp, generator.generate(-1));
}

test "TOTP propagates secret and digit validation" {
    const empty = Totp{ .secret = "" };
    try testing.expectError(error.EmptySecret, empty.generate(59));

    const bad_digits = Totp{ .secret = test_secret, .digits = 7 };
    try testing.expectError(error.InvalidDigits, bad_digits.generate(59));
}

test "TOTP keeps counters wider than 32 bits" {
    const generator = Totp{ .secret = test_secret, .period = 1 };
    const timestamp: i64 = 4294967296;
    const expected = try hotp.generate(test_secret, 4294967296, 6);
    try expectCode(generator, timestamp, expected);
}
