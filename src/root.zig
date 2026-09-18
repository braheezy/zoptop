pub const hotp = @import("hotp.zig");
pub const Totp = @import("totp.zig").Totp;
pub const otpauth = @import("otpauth.zig");
pub const Account = @import("Account.zig");
const codes = @import("codes.zig");
const Algorithm = @import("algorithm.zig").Algorithm;
const format = @import("format.zig");
const vault = @import("vault.zig");
const store = @import("store.zig");

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

const one_account_bytes = "ZOTP\x00\x01\x00\x00\x00\x01" ++
    "\x01\x06\x00\x00\x00\x1e" ++
    "\x00\x00\x00\x00" ++
    "\x00\x00\x00\x01a" ++
    "\x00\x00\x00\x01f";

fn expectSameAccount(a: Account, b: Account) !void {
    try testing.expectEqualStrings(a.issuer, b.issuer);
    try testing.expectEqualStrings(a.name, b.name);
    try testing.expectEqualSlices(u8, a.secret, b.secret);
    try testing.expectEqual(a.algorithm, b.algorithm);
    try testing.expectEqual(a.digits, b.digits);
    try testing.expectEqual(a.period, b.period);
}

fn expectBadFormat(bytes: []const u8, expected: anyerror) !void {
    if (format.decode(testing.allocator, bytes)) |db| {
        db.deinit(testing.allocator);
        return error.TestUnexpectedSuccess;
    } else |err| try testing.expectEqual(expected, err);
}

test "format: known bytes and empty database" {
    const a = try otpauth.parse(testing.allocator, "otpauth://totp/a?secret=MY");
    defer a.deinit(testing.allocator);
    const bytes = try format.encode(testing.allocator, &.{a});
    defer testing.allocator.free(bytes);
    try testing.expectEqualSlices(u8, one_account_bytes, bytes);
    const db = try format.decode(testing.allocator, one_account_bytes);
    defer db.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 1), db.accounts.len);
    try expectSameAccount(a, db.accounts[0]);
    const empty = try format.encode(testing.allocator, &.{});
    defer testing.allocator.free(empty);
    try testing.expectEqualSlices(u8, "ZOTP\x00\x01\x00\x00\x00\x00", empty);
    const empty_db = try format.decode(testing.allocator, empty);
    defer empty_db.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 0), empty_db.accounts.len);
}

test "format: multiple accounts survive without the source bytes" {
    const a = try otpauth.parse(testing.allocator, uri256);
    defer a.deinit(testing.allocator);
    const b = try otpauth.parse(testing.allocator, "otpauth://totp/caf%C3%A9?secret=MY&period=60");
    defer b.deinit(testing.allocator);
    const bytes = try format.encode(testing.allocator, &.{ a, b });
    defer testing.allocator.free(bytes);
    const db = try format.decode(testing.allocator, bytes);
    defer db.deinit(testing.allocator);
    @memset(bytes, 0); // Decoded accounts must have their own copies.
    try testing.expectEqual(@as(usize, 2), db.accounts.len);
    try expectSameAccount(a, db.accounts[0]);
    try expectSameAccount(b, db.accounts[1]);
    try expectCode(db.accounts[0], 59, "46119246");
}

test "format: rejects truncation and invalid fields" {
    for (0..one_account_bytes.len) |len| {
        try expectBadFormat(one_account_bytes[0..len], error.InvalidFormat);
    }
    try expectBadFormat(one_account_bytes ++ "x", error.InvalidFormat);
    var changed = one_account_bytes.*;
    changed[5] = 2;
    try expectBadFormat(&changed, error.UnsupportedVersion);
    changed = one_account_bytes.*;
    changed[10] = 255; // Unknown algorithm.
    try expectBadFormat(&changed, error.InvalidFormat);
    changed = one_account_bytes.*;
    changed[11] = 7;
    try expectBadFormat(&changed, error.InvalidFormat);
    changed = one_account_bytes.*;
    @memset(changed[16..20], 255); // Impossible issuer length.
    try expectBadFormat(&changed, error.InvalidFormat);
}

const cheap = vault.SealOptions{ .params = .{ .t = 1, .m = 32, .p = 1 } };

fn expectVaultError(bytes: []const u8, password: []const u8, expected: anyerror) !void {
    if (vault.open(testing.allocator, testing.io, password, bytes)) |plain| {
        defer testing.allocator.free(plain);
        return error.TestUnexpectedSuccess;
    } else |err| try testing.expectEqual(expected, err);
}

test "vault: password, random salt and nonce, and authentication" {
    const encrypted = try vault.seal(testing.allocator, testing.io, "test password", "hello", cheap);
    defer testing.allocator.free(encrypted);
    const another = try vault.seal(testing.allocator, testing.io, "test password", "hello", cheap);
    defer testing.allocator.free(another);
    try testing.expectEqual(@as(usize, 85), encrypted.len);
    try testing.expect(!std.mem.eql(u8, encrypted[20..36], another[20..36]));
    try testing.expect(!std.mem.eql(u8, encrypted[36..60], another[36..60]));
    const plain = try vault.open(testing.allocator, testing.io, "test password", encrypted);
    defer testing.allocator.free(plain);
    try testing.expectEqualStrings("hello", plain);
    try expectVaultError(encrypted, "wrong password", error.AuthenticationFailed);
    for ([_]usize{ 20, 36, 64, encrypted.len - 1 }) |index| {
        encrypted[index] ^= 1; // Salt, nonce, ciphertext, then tag.
        try expectVaultError(encrypted, "test password", error.AuthenticationFailed);
        encrypted[index] ^= 1;
    }
    for (0..encrypted.len) |len| {
        try expectVaultError(encrypted[0..len], "test password", error.InvalidVault);
    }
    encrypted[4] = 2;
    try expectVaultError(encrypted, "test password", error.UnsupportedVersion);
    encrypted[4] = 1;
    @memset(encrypted[12..16], 255);
    try expectVaultError(encrypted, "test password", error.InvalidKdfParameters);
}

fn wholeMemoryFlow(allocator: std.mem.Allocator) anyerror!void {
    const account = try otpauth.parse(allocator, uri1);
    defer account.deinit(allocator);
    const second = try otpauth.parse(allocator, uri256);
    defer second.deinit(allocator);
    const bytes = try format.encode(allocator, &.{ account, second });
    defer allocator.free(bytes);
    const encrypted = try vault.seal(allocator, testing.io, "test password", bytes, cheap);
    defer allocator.free(encrypted);
    const plain = try vault.open(allocator, testing.io, "test password", encrypted);
    defer allocator.free(plain);
    const db = try format.decode(allocator, plain);
    defer db.deinit(allocator);
    try testing.expectEqual(@as(usize, 2), db.accounts.len);
    try expectCode(db.accounts[0], 1111111109, "07081804");
    try expectCode(db.accounts[1], 59, "46119246");
}

test "vault: import encrypt reopen and generate, including allocation failures" {
    try testing.checkAllAllocationFailures(testing.allocator, wholeMemoryFlow, .{});
}

test "store: import three accounts, save, reopen, generate, replace" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const a = try otpauth.parse(testing.allocator, uri1);
    defer a.deinit(testing.allocator);
    const b = try otpauth.parse(testing.allocator, uri256);
    defer b.deinit(testing.allocator);
    const c = try otpauth.parse(testing.allocator, uri512);
    defer c.deinit(testing.allocator);
    try store.save(testing.allocator, testing.io, tmp.dir, "accounts", "password", &.{ a, b, c }, cheap);
    const db = try store.load(testing.allocator, testing.io, tmp.dir, "accounts", "password");
    defer db.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 3), db.accounts.len);
    try expectSameAccount(a, db.accounts[0]);
    try expectSameAccount(b, db.accounts[1]);
    try expectSameAccount(c, db.accounts[2]);
    try expectCode(db.accounts[0], 59, "94287082");
    try expectCode(db.accounts[1], 59, "46119246");
    try expectCode(db.accounts[2], 59, "90693936");
    if (store.load(testing.allocator, testing.io, tmp.dir, "accounts", "wrong")) |unexpected| {
        unexpected.deinit(testing.allocator);
        return error.TestUnexpectedSuccess;
    } else |err| try testing.expectEqual(error.AuthenticationFailed, err);
    // Replacing with an empty database is a valid save.
    try store.save(testing.allocator, testing.io, tmp.dir, "accounts", "password", &.{}, cheap);
    const empty = try store.load(testing.allocator, testing.io, tmp.dir, "accounts", "password");
    defer empty.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 0), empty.accounts.len);
}

test "store: rejected save preserves the previous file byte for byte" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const account = try otpauth.parse(testing.allocator, uri1);
    defer account.deinit(testing.allocator);
    try store.save(testing.allocator, testing.io, tmp.dir, "accounts", "password", &.{account}, cheap);
    const before = try tmp.dir.readFileAlloc(testing.io, "accounts", testing.allocator, .limited(1024 * 1024));
    defer testing.allocator.free(before);
    // Borrow the original allocations for this call; don't deinit bad separately.
    var bad = account;
    bad.period = 0;
    try testing.expectError(error.InvalidAccount, store.save(testing.allocator, testing.io, tmp.dir, "accounts", "password", &.{bad}, cheap));
    const after = try tmp.dir.readFileAlloc(testing.io, "accounts", testing.allocator, .limited(1024 * 1024));
    defer testing.allocator.free(after);
    try testing.expectEqualSlices(u8, before, after);
}
