const std = @import("std");
const Account = @import("Account.zig");
const vault = @import("vault.zig");
const format = @import("format.zig");

const max_vault_size = 4 * 1024 * 1024 + 80;

fn validateFilename(filename: []const u8) !void {
    if (filename.len == 0 or
        !std.unicode.utf8ValidateSlice(filename) or
        std.mem.eql(u8, filename, ".") or
        std.mem.eql(u8, filename, "..")) return error.InvalidFile;
    for (filename) |byte| {
        if (byte == '/' or byte == '\\' or byte == 0) return error.InvalidFile;
    }
}

pub fn save(
    al: std.mem.Allocator,
    io: std.Io,
    dir: std.Io.Dir,
    filename: []const u8,
    password: []const u8,
    accounts: []const Account,
    options: vault.SealOptions,
) !void {
    try validateFilename(filename);

    const plaintext = try format.encode(al, accounts);
    defer {
        std.crypto.secureZero(u8, plaintext);
        al.free(plaintext);
    }
    const encrypted_bytes = try vault.seal(al, io, password, plaintext, options);
    defer al.free(encrypted_bytes);

    var atomic_file = try dir.createFileAtomic(
        io,
        filename,
        .{ .replace = true, .permissions = .fromMode(0o600) },
    );
    defer atomic_file.deinit(io);

    try atomic_file.file.writeStreamingAll(io, encrypted_bytes);
    try atomic_file.file.sync(io);
    try atomic_file.replace(io);
}

pub fn load(
    al: std.mem.Allocator,
    io: std.Io,
    dir: std.Io.Dir,
    filename: []const u8,
    password: []const u8,
) !format.Database {
    try validateFilename(filename);

    const encrypted_bytes = dir.readFileAlloc(io, filename, al, .limited(max_vault_size + 1)) catch |err| switch (err) {
        error.StreamTooLong => return error.InvalidVault,
        else => return err,
    };
    defer al.free(encrypted_bytes);
    if (encrypted_bytes.len > max_vault_size) return error.InvalidVault;
    const plaintext = try vault.open(al, io, password, encrypted_bytes);
    defer {
        std.crypto.secureZero(u8, plaintext);
        al.free(plaintext);
    }
    return try format.decode(al, plaintext);
}

const testing = std.testing;
const test_options: vault.SealOptions = .{ .params = .{ .t = 1, .m = 32, .p = 1 } };

test "store rejects separators and NUL anywhere in filenames" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    for ([_][]const u8{
        "",            ".",             "..",         "/",            "\\",           "/accounts",    "accounts/", "sub/accounts",
        "../accounts", "sub\\accounts", "accounts\\", "\x00accounts", "acc\x00ounts", "accounts\x00", "\xff",
    }) |filename| {
        errdefer std.debug.print("filename bytes: {x}\n", .{filename});
        try testing.expectError(error.InvalidFile, save(testing.allocator, testing.io, tmp.dir, filename, "password", &.{}, test_options));
        if (load(testing.allocator, testing.io, tmp.dir, filename, "password")) |db| {
            db.deinit(testing.allocator);
            return error.TestUnexpectedSuccess;
        } else |err| try testing.expectEqual(error.InvalidFile, err);
    }
}

test "store loads the maximum database plus the 80 byte vault overhead" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const name = [_]u8{'a'} ** 4077;
    const accounts = try testing.allocator.alloc(Account, 1024);
    defer testing.allocator.free(accounts);
    for (accounts) |*account| account.* = .{ .issuer = "", .name = &name, .secret = "f" };
    // 1024 records of 4096 bytes, minus ten bytes to fit the database header.
    accounts[1023].name = name[0..4067];
    const filename = "café.accounts";
    try save(testing.allocator, testing.io, tmp.dir, filename, "password", accounts, test_options);
    const bytes = try tmp.dir.readFileAlloc(testing.io, filename, testing.allocator, .limited(max_vault_size + 1));
    defer testing.allocator.free(bytes);
    try testing.expectEqual(@as(usize, max_vault_size), bytes.len);
    const db = try load(testing.allocator, testing.io, tmp.dir, filename, "password");
    defer db.deinit(testing.allocator);
    try testing.expectEqual(accounts.len, db.accounts.len);
    try testing.expectEqualStrings(accounts[1023].name, db.accounts[1023].name);
    try testing.expectEqualStrings("f", db.accounts[1023].secret);
}

test "store rejects files larger than the vault limit" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const bytes = try testing.allocator.alloc(u8, max_vault_size + 2);
    defer testing.allocator.free(bytes);
    @memset(bytes, 0);
    for ([_]usize{ max_vault_size + 1, max_vault_size + 2 }) |size| {
        try tmp.dir.writeFile(testing.io, .{ .sub_path = "oversized", .data = bytes[0..size] });
        if (load(testing.allocator, testing.io, tmp.dir, "oversized", "password")) |db| {
            db.deinit(testing.allocator);
            return error.TestUnexpectedSuccess;
        } else |err| try testing.expectEqual(error.InvalidVault, err);
    }
}
