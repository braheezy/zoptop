const std = @import("std");
const totp = @import("totp");

pub fn matches(account: totp.Account, query: []const u8) bool {
    return containsIgnoreAsciiCase(account.issuer, query) or
        containsIgnoreAsciiCase(account.name, query);
}

pub fn rebuild(
    al: std.mem.Allocator,
    results: *std.ArrayList(usize),
    accounts: []const totp.Account,
    query: []const u8,
) !void {
    // This can fail. The old results are still untouched if it fails.
    try results.ensureTotalCapacity(al, accounts.len);

    // No allocation happens after this point.
    results.clearRetainingCapacity();

    for (accounts, 0..) |account, index| {
        if (matches(account, query)) {
            results.appendAssumeCapacity(index);
        }
    }
}

fn foldAscii(byte: u8) u8 {
    if (byte >= 'A' and byte <= 'Z')
        return byte + ('a' - 'A');

    return byte;
}
fn containsIgnoreAsciiCase(text: []const u8, query: []const u8) bool {
    if (query.len == 0)
        return true;

    if (query.len > text.len)
        return false;

    const last_start = text.len - query.len;

    for (0..last_start + 1) |start| {
        var matched = true;

        for (query, 0..) |query_byte, offset| {
            if (foldAscii(text[start + offset]) != foldAscii(query_byte)) {
                matched = false;
                break;
            }
        }

        if (matched)
            return true;
    }

    return false;
}

const testing = std.testing;

const test_accounts = [_]totp.Account{
    .{ .issuer = "Acme", .name = "alice@example.com", .secret = "secret-a" },
    .{ .issuer = "Research", .name = "Bob", .secret = "secret-b" },
    .{ .issuer = "Acme", .name = "carol", .secret = "secret-c" },
};

fn expectIndexes(results: std.ArrayList(usize), expected: []const usize) !void {
    try testing.expectEqualSlices(usize, expected, results.items);
}

test "filter empty query returns every account in order" {
    var results: std.ArrayList(usize) = .empty;
    defer results.deinit(testing.allocator);

    try rebuild(testing.allocator, &results, &test_accounts, "");
    try expectIndexes(results, &.{ 0, 1, 2 });
}

test "filter matches ASCII letters without regard to case" {
    var results: std.ArrayList(usize) = .empty;
    defer results.deinit(testing.allocator);

    try rebuild(testing.allocator, &results, &test_accounts, "ALICE");
    try expectIndexes(results, &.{0});

    try rebuild(testing.allocator, &results, &test_accounts, "bOb");
    try expectIndexes(results, &.{1});
}

test "filter searches issuer and preserves account order" {
    var results: std.ArrayList(usize) = .empty;
    defer results.deinit(testing.allocator);

    try rebuild(testing.allocator, &results, &test_accounts, "acme");
    try expectIndexes(results, &.{ 0, 2 });
}

test "filter returns no indexes when nothing matches" {
    var results: std.ArrayList(usize) = .empty;
    defer results.deinit(testing.allocator);

    try rebuild(testing.allocator, &results, &test_accounts, "does-not-exist");
    try testing.expectEqual(@as(usize, 0), results.items.len);
}

test "filter does not search secrets" {
    var results: std.ArrayList(usize) = .empty;
    defer results.deinit(testing.allocator);

    try rebuild(testing.allocator, &results, &test_accounts, "secret-a");
    try testing.expectEqual(@as(usize, 0), results.items.len);
}
