const std = @import("std");
const testing = std.testing;
const Algorithm = @import("algorithm.zig").Algorithm;

pub fn generate(secret: []const u8, counter: u64, digits: u8) !u32 {
    if (secret.len == 0) return error.EmptySecret;

    var message: [8]u8 = undefined;
    std.mem.writeInt(u64, &message, counter, .big);
    var digest: [20]u8 = undefined;
    std.crypto.auth.hmac.HmacSha1.create(&digest, &message, secret);
    const offset = digest[19] & 0x0f;
    var value = std.mem.readInt(u32, digest[offset..][0..4], .big);
    value &= 0x7fffffff;

    const modulus: u32 = switch (digits) {
        6 => 1_000_000,
        8 => 100_000_000,
        else => return error.InvalidDigits,
    };

    return value % modulus;
}

pub fn generateWithAlgorithm(secret: []const u8, counter: u64, digits: u8, algorithm: Algorithm) !u32 {
    if (secret.len == 0) return error.EmptySecret;

    var message: [8]u8 = undefined;
    std.mem.writeInt(u64, &message, counter, .big);
    var value: u32 = 0;

    switch (algorithm) {
        .sha1 => {
            var digest: [20]u8 = undefined;
            std.crypto.auth.hmac.HmacSha1.create(&digest, &message, secret);
            const offset = digest[19] & 0x0f;
            value = std.mem.readInt(u32, digest[offset..][0..4], .big);
        },
        .sha256 => {
            var digest: [32]u8 = undefined;
            std.crypto.auth.hmac.sha2.HmacSha256.create(&digest, &message, secret);
            const offset = digest[31] & 0x0f;
            value = std.mem.readInt(u32, digest[offset..][0..4], .big);
        },
        .sha512 => {
            var digest: [64]u8 = undefined;
            std.crypto.auth.hmac.sha2.HmacSha512.create(&digest, &message, secret);
            const offset = digest[63] & 0x0f;
            value = std.mem.readInt(u32, digest[offset..][0..4], .big);
        },
    }

    value &= 0x7fffffff;

    const modulus: u32 = switch (digits) {
        6 => 1_000_000,
        8 => 100_000_000,
        else => return error.InvalidDigits,
    };

    return value % modulus;
}

const test_secret = "12345678901234567890";

// A tiny helper adds the failing counter to table-driven test output.
fn expectCode(counter: u64, expected: u32) !void {
    const actual = try generate(test_secret, counter, 6);
    errdefer std.debug.print("\nHOTP counter: {d}\n", .{counter});
    try testing.expectEqual(expected, actual);
}

test "HOTP RFC 4226 counters 0 through 9" {
    const expected = [_]u32{
        755224, 287082, 359152, 969429, 338314,
        254676, 287922, 162583, 399871, 520489,
    };

    for (expected, 0..) |code, counter| {
        try expectCode(@intCast(counter), code);
    }
}

test "HOTP rejects an empty secret" {
    try testing.expectError(error.EmptySecret, generate("", 0, 6));
}

test "HOTP accepts only six or eight digits" {
    for ([_]u8{ 0, 5, 7, 9, 255 }) |digits| {
        try testing.expectError(
            error.InvalidDigits,
            generate(test_secret, 0, digits),
        );
    }
}
