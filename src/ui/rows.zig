const std = @import("std");
const totp = @import("totp");

pub const RowText = struct {
    code: [8]u8,
    code_len: usize,
    remaining: [7]u8,
    remaining_len: usize,
};

pub fn build(account: totp.Account, timestamp: i64) !RowText {
    var result: RowText = undefined;
    const generator = account.generator();
    const number = try generator.generate(timestamp);

    const code = try totp.codes.format(number, account.digits, &result.code);
    result.code_len = code.len;

    const seconds = try generator.remaining(timestamp);

    if (seconds > 99999) {
        @memcpy(&result.remaining, ">99999s");
        result.remaining_len = 7;
    } else {
        const text = try std.fmt.bufPrint(&result.remaining, "{d}s", .{seconds});
        result.remaining_len = text.len;
    }

    return result;
}

const testing = std.testing;
test "row text preserves leading zeros and resets remaining time" {
    const account: totp.Account = .{
        .issuer = "",
        .name = "alice",
        .secret = "12345678901234567890",
        .digits = 8,
    };
    const before = try build(account, 1111111109);
    try testing.expectEqualStrings("07081804", before.code[0..before.code_len]);
    try testing.expectEqualStrings("1s", before.remaining[0..before.remaining_len]);
    const after = try build(account, 1111111110);
    try testing.expectEqualStrings("30s", after.remaining[0..after.remaining_len]);
}

test "row text uses each account's period" {
    const account: totp.Account = .{
        .issuer = "",
        .name = "alice",
        .secret = "12345678901234567890",
        .period = 60,
    };
    const row = try build(account, 59);
    try testing.expectEqualStrings("755224", row.code[0..row.code_len]);
    try testing.expectEqualStrings("1s", row.remaining[0..row.remaining_len]);
}
