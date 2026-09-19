const std = @import("std");
const Account = @import("Account.zig");

const max_database_size = 4 * 1024 * 1024;
const max_accounts = 1024;
const max_name_size = 4096;
const max_secret_size = 1024;

fn validName(bytes: []const u8) bool {
    if (bytes.len > max_name_size or !std.unicode.utf8ValidateSlice(bytes)) return false;
    for (bytes) |byte| {
        if (byte < 0x20 or byte == 0x7f or byte == ':') return false;
    }
    return true;
}

fn validAccount(account: Account) bool {
    return validName(account.issuer) and validName(account.name) and
        account.name.len > 0 and account.secret.len > 0 and
        account.secret.len <= max_secret_size and
        (account.digits == 6 or account.digits == 8) and account.period > 0;
}

pub const Database = struct {
    accounts: []Account,

    pub fn deinit(self: Database, al: std.mem.Allocator) void {
        for (self.accounts) |acc| {
            acc.deinit(al);
        }
        al.free(self.accounts);
    }
};

pub fn encode(al: std.mem.Allocator, accounts: []const Account) ![]u8 {
    if (accounts.len > max_accounts) return error.InvalidAccount;

    var size: usize = 10;

    for (accounts) |account| {
        if (!validAccount(account)) return error.InvalidAccount;

        size += 18 + account.issuer.len + account.name.len + account.secret.len;
    }
    if (size > max_database_size) return error.InvalidAccount;

    const output = try al.alloc(u8, size);
    errdefer al.free(output);

    var i: usize = 0;
    @memcpy(output[i .. i + 4], "ZOTP");
    i += 4;

    var version_bytes: [2]u8 = undefined;
    std.mem.writeInt(u16, &version_bytes, 1, .big);
    @memcpy(output[i .. i + 2], &version_bytes);
    i += 2;

    var account_count_bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &account_count_bytes, @intCast(accounts.len), .big);
    @memcpy(output[i .. i + 4], &account_count_bytes);
    i += 4;

    for (accounts) |account| {
        var buf: [4]u8 = undefined;

        const algo: u8 = switch (account.algorithm) {
            .sha1 => 1,
            .sha256 => 2,
            .sha512 => 3,
        };
        std.mem.writeInt(u8, &buf[0], algo, .big);
        output[i] = buf[0];
        i += 1;

        std.mem.writeInt(u8, &buf[0], account.digits, .big);
        output[i] = buf[0];
        i += 1;

        std.mem.writeInt(u32, &buf, account.period, .big);
        @memcpy(output[i .. i + 4], &buf);
        i += 4;

        std.mem.writeInt(u32, &buf, @intCast(account.issuer.len), .big);
        @memcpy(output[i .. i + 4], &buf);
        i += 4;
        @memcpy(output[i .. i + account.issuer.len], account.issuer);
        i += account.issuer.len;

        std.mem.writeInt(u32, &buf, @intCast(account.name.len), .big);
        @memcpy(output[i .. i + 4], &buf);
        i += 4;
        @memcpy(output[i .. i + account.name.len], account.name);
        i += account.name.len;

        std.mem.writeInt(u32, &buf, @intCast(account.secret.len), .big);
        @memcpy(output[i .. i + 4], &buf);
        i += 4;
        @memcpy(output[i .. i + account.secret.len], account.secret);
        i += account.secret.len;
    }

    return output;
}

// Every read goes through this check, including zero-length fields.
fn take(bytes: []const u8, position: *usize, count: usize) ![]const u8 {
    if (count > bytes.len - position.*) return error.InvalidFormat;
    const result = bytes[position.*..][0..count];
    position.* += count;
    return result;
}

fn readU32(bytes: []const u8, position: *usize) !u32 {
    const field = try take(bytes, position, 4);
    return std.mem.readInt(u32, field[0..4], .big);
}

pub fn decode(al: std.mem.Allocator, bytes: []const u8) !Database {
    if (bytes.len < 10 or bytes.len > max_database_size) return error.InvalidFormat;
    var i: usize = 0;
    if (!std.mem.eql(u8, try take(bytes, &i, 4), "ZOTP")) return error.InvalidFormat;
    const version = try take(bytes, &i, 2);
    if (std.mem.readInt(u16, version[0..2], .big) != 1) return error.UnsupportedVersion;
    const account_count = try readU32(bytes, &i);
    if (account_count > max_accounts) return error.InvalidFormat;

    var accounts: std.ArrayList(Account) = try .initCapacity(al, account_count);
    errdefer {
        for (accounts.items) |account| account.deinit(al);
        accounts.deinit(al);
    }

    for (0..account_count) |_| {
        const algo = (try take(bytes, &i, 1))[0];
        const digits = (try take(bytes, &i, 1))[0];
        const period = try readU32(bytes, &i);
        const issuer_len = try readU32(bytes, &i);
        if (issuer_len > max_name_size) return error.InvalidFormat;
        const issuer_bytes = try take(bytes, &i, issuer_len);
        const name_len = try readU32(bytes, &i);
        if (name_len > max_name_size) return error.InvalidFormat;
        const name_bytes = try take(bytes, &i, name_len);
        const secret_len = try readU32(bytes, &i);
        if (secret_len > max_secret_size) return error.InvalidFormat;
        const secret_bytes = try take(bytes, &i, secret_len);

        // Validate borrowed slices before allocating copies of the fields.
        var account = Account{
            .issuer = issuer_bytes,
            .name = name_bytes,
            .secret = secret_bytes,
            .algorithm = switch (algo) {
                1 => .sha1,
                2 => .sha256,
                3 => .sha512,
                else => return error.InvalidFormat,
            },
            .digits = digits,
            .period = period,
        };
        if (!validAccount(account)) return error.InvalidFormat;
        account.issuer = try al.dupe(u8, issuer_bytes);
        errdefer al.free(account.issuer);
        account.name = try al.dupe(u8, name_bytes);
        errdefer al.free(account.name);
        account.secret = try al.dupe(u8, secret_bytes);
        errdefer al.free(account.secret);
        accounts.appendAssumeCapacity(account);
    }

    if (i != bytes.len) return error.InvalidFormat;
    return .{ .accounts = try accounts.toOwnedSlice(al) };
}

const testing = std.testing;

// Deliberately bypass encode's validation to make malformed input for decode.
fn testAccountBytes(account: Account) ![]u8 {
    const bytes = try testing.allocator.alloc(u8, 28 + account.issuer.len + account.name.len + account.secret.len);
    @memcpy(bytes[0..10], "ZOTP\x00\x01\x00\x00\x00\x01");
    bytes[10] = 1;
    bytes[11] = account.digits;
    std.mem.writeInt(u32, bytes[12..16], account.period, .big);
    var position: usize = 16;
    for ([_][]const u8{ account.issuer, account.name, account.secret }) |field| {
        std.mem.writeInt(u32, bytes[position..][0..4], @intCast(field.len), .big);
        position += 4;
        @memcpy(bytes[position..][0..field.len], field);
        position += field.len;
    }
    return bytes;
}

fn expectInvalidAccount(account: Account) !void {
    if (encode(testing.allocator, &.{account})) |bytes| {
        testing.allocator.free(bytes);
        return error.TestUnexpectedSuccess;
    } else |err| try testing.expectEqual(error.InvalidAccount, err);
    const bytes = try testAccountBytes(account);
    defer testing.allocator.free(bytes);
    try expectInvalidBytes(bytes);
}

fn expectInvalidBytes(bytes: []const u8) !void {
    if (decode(testing.allocator, bytes)) |db| {
        db.deinit(testing.allocator);
        return error.TestUnexpectedSuccess;
    } else |err| try testing.expectEqual(error.InvalidFormat, err);
}

test "format validates account fields on both encode and decode" {
    const good: Account = .{ .issuer = "Example", .name = "alice", .secret = "f" };
    for ([_][]const u8{ "", "alice:work", "a\x00b", "a\x1fb", "a\x7fb", "\xff", "\xc3" }) |name| {
        errdefer std.debug.print("invalid name: {x}\n", .{name});
        var bad = good;
        bad.name = name;
        try expectInvalidAccount(bad);
    }
    for ([_][]const u8{ "A:B", "A\nB", "\x00", "\x7f", "\xff", "\xc3" }) |issuer| {
        errdefer std.debug.print("invalid issuer: {x}\n", .{issuer});
        var bad = good;
        bad.issuer = issuer;
        try expectInvalidAccount(bad);
    }
    var bad = good;
    bad.secret = "";
    try expectInvalidAccount(bad);
    bad = good;
    bad.period = 0;
    try expectInvalidAccount(bad);
    for ([_]u8{ 0, 5, 7, 9, 255 }) |digits| {
        bad = good;
        bad.digits = digits;
        try expectInvalidAccount(bad);
    }
}

test "format accepts field limits and rejects one byte over" {
    const name = [_]u8{'a'} ** 4097;
    const secret = [_]u8{0xff} ** 1025;
    const good: Account = .{ .issuer = name[0..4096], .name = name[0..4096], .secret = secret[0..1024], .digits = 8, .period = 0xffffffff };
    const bytes = try encode(testing.allocator, &.{good});
    defer testing.allocator.free(bytes);
    const db = try decode(testing.allocator, bytes);
    defer db.deinit(testing.allocator);
    try testing.expectEqualStrings(good.name, db.accounts[0].name);
    try testing.expectEqualStrings(good.issuer, db.accounts[0].issuer);
    try testing.expectEqualSlices(u8, good.secret, db.accounts[0].secret);
    try testing.expectEqual(good.period, db.accounts[0].period);
    var bad = good;
    bad.name = &name;
    try expectInvalidAccount(bad);
    bad = good;
    bad.issuer = &name;
    try expectInvalidAccount(bad);
    bad = good;
    bad.secret = &secret;
    try expectInvalidAccount(bad);
}

test "format accepts exactly 1024 accounts and 4 MiB" {
    const name = [_]u8{'a'} ** 4077;
    const accounts = try testing.allocator.alloc(Account, 1025);
    defer testing.allocator.free(accounts);
    for (accounts) |*account| account.* = .{ .issuer = "", .name = &name, .secret = "f" };
    // Each record is 4096 bytes; subtract ten to leave room for the header.
    accounts[1023].name = name[0..4067];
    const bytes = try encode(testing.allocator, accounts[0..1024]);
    defer testing.allocator.free(bytes);
    try testing.expectEqual(@as(usize, 4 * 1024 * 1024), bytes.len);
    const db = try decode(testing.allocator, bytes);
    defer db.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 1024), db.accounts.len);
    // One additional byte makes the database too large, with every field valid.
    accounts[1023].name = name[0..4068];
    try testing.expectError(error.InvalidAccount, encode(testing.allocator, accounts[0..1024]));
    const oversized = try testing.allocator.alloc(u8, bytes.len + 1);
    defer testing.allocator.free(oversized);
    @memcpy(oversized[0..bytes.len], bytes);
    oversized[bytes.len] = 0;
    try expectInvalidBytes(oversized);
    // Small records isolate the account count limit from the byte limit.
    for (accounts) |*account| account.name = "a";
    try testing.expectError(error.InvalidAccount, encode(testing.allocator, accounts));
    var header = "ZOTP\x00\x01\x00\x00\x04\x01".*;
    try expectInvalidBytes(&header);
}

fn decodeAllocationCase(al: std.mem.Allocator, bytes: []const u8) !void {
    const db = try decode(al, bytes);
    defer db.deinit(al);
    try testing.expectEqual(@as(usize, 2), db.accounts.len);
}

test "format cleans up when decoding a later account fails" {
    const account: Account = .{ .issuer = "", .name = "café", .secret = "\x00\xff" };
    const bytes = try encode(testing.allocator, &.{ account, account });
    defer testing.allocator.free(bytes);
    try testing.checkAllAllocationFailures(testing.allocator, decodeAllocationCase, .{bytes});
    // A zero period in the second account also frees the completed first account.
    const second_start = 10 + 18 + account.name.len + account.secret.len;
    @memset(bytes[second_start + 2 ..][0..4], 0);
    try expectInvalidBytes(bytes);
}
