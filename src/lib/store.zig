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

fn expectDirectoryContents(dir: std.Io.Dir, expected_name: ?[]const u8) !void {
    var iterator = dir.iterate();
    var count: usize = 0;
    while (try iterator.next(testing.io)) |entry| {
        errdefer std.debug.print("unexpected leftover file: {s}\n", .{entry.name});
        try testing.expectEqualStrings(expected_name orelse return error.TestUnexpectedFile, entry.name);
        count += 1;
    }
    try testing.expectEqual(@as(usize, if (expected_name != null) 1 else 0), count);
}

fn expectLoadError(dir: std.Io.Dir, password: []const u8, expected: anyerror) !void {
    if (load(testing.allocator, testing.io, dir, "accounts", password)) |db| {
        db.deinit(testing.allocator);
        return error.TestUnexpectedSuccess;
    } else |err| try testing.expectEqual(expected, err);
}

test "store cleans up partial writes, failed syncs, and failed replacements" {
    // Only the chosen I/O operation fails. All file creation and cleanup still
    // use real files, without relying on chmod or the current user's privileges.
    const Fail = struct {
        fn write(userdata: ?*anyopaque, operation: std.Io.Operation) std.Io.Cancelable!std.Io.Operation.Result {
            switch (operation) {
                .file_write_streaming => |request| {
                    // Leave real partial data in the temporary file before failing.
                    request.file.writeStreamingAll(testing.io, request.data[0][0..7]) catch |err| switch (err) {
                        error.Canceled => return error.Canceled,
                        else => |other| return .{ .file_write_streaming = other },
                    };
                    return .{ .file_write_streaming = error.NoSpaceLeft };
                },
                else => return testing.io.vtable.operate(userdata, operation),
            }
        }
        fn sync(_: ?*anyopaque, _: std.Io.File) std.Io.File.SyncError!void {
            return error.InputOutput;
        }
        fn rename(_: ?*anyopaque, _: std.Io.Dir, _: []const u8, _: std.Io.Dir, _: []const u8) std.Io.Dir.RenameError!void {
            return error.AccessDenied;
        }
    };
    const stages = [_]enum { write, sync, rename }{ .write, .sync, .rename };
    for (stages) |stage| {
        for ([_]bool{ false, true }) |existing| {
            errdefer std.debug.print("save failure: {s}, existing file: {}\n", .{ @tagName(stage), existing });
            var tmp = testing.tmpDir(.{ .iterate = true });
            defer tmp.cleanup();
            if (existing) try save(testing.allocator, testing.io, tmp.dir, "accounts", "old password", &.{}, test_options);
            const before = if (existing)
                try tmp.dir.readFileAlloc(testing.io, "accounts", testing.allocator, .limited(1024))
            else
                null;
            defer if (before) |bytes| testing.allocator.free(bytes);
            var vtable = testing.io.vtable.*;
            const expected: anyerror = switch (stage) {
                .write => blk: {
                    vtable.operate = Fail.write;
                    break :blk error.NoSpaceLeft;
                },
                .sync => blk: {
                    vtable.fileSync = Fail.sync;
                    break :blk error.InputOutput;
                },
                .rename => blk: {
                    vtable.dirRename = Fail.rename;
                    break :blk error.AccessDenied;
                },
            };
            const failing_io: std.Io = .{ .userdata = testing.io.userdata, .vtable = &vtable };
            const account: Account = .{ .issuer = "", .name = "alice", .secret = "f" };
            try testing.expectError(expected, save(testing.allocator, failing_io, tmp.dir, "accounts", "new password", &.{account}, test_options));
            try expectDirectoryContents(tmp.dir, if (existing) "accounts" else null);
            if (before) |bytes| {
                const after = try tmp.dir.readFileAlloc(testing.io, "accounts", testing.allocator, .limited(1024));
                defer testing.allocator.free(after);
                try testing.expectEqualSlices(u8, bytes, after);
                const db = try load(testing.allocator, testing.io, tmp.dir, "accounts", "old password");
                defer db.deinit(testing.allocator);
                try testing.expectEqual(@as(usize, 0), db.accounts.len);
            } else {
                try expectLoadError(tmp.dir, "password", error.FileNotFound);
            }
        }
    }
}

test "store creates and replaces files with private permissions and no leftovers" {
    if (@import("builtin").os.tag != .macos and @import("builtin").os.tag != .linux)
        return error.SkipZigTest;
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    for (0..2) |_| {
        try save(testing.allocator, testing.io, tmp.dir, "accounts", "password", &.{}, test_options);
        const stat = try tmp.dir.statFile(testing.io, "accounts", .{});
        try testing.expectEqual(@as(std.posix.mode_t, 0o600), stat.permissions.toMode() & 0o777);
        try expectDirectoryContents(tmp.dir, "accounts");
    }
}

test "store missing file remains missing after load" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    try expectLoadError(tmp.dir, "password", error.FileNotFound);
    try expectDirectoryContents(tmp.dir, null);
}

test "store rejects corrupted files and wrong passwords without changing the file" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const encrypted = try vault.seal(testing.allocator, testing.io, "password", "ZOTP\x00\x01\x00\x00\x00\x00", test_options);
    defer testing.allocator.free(encrypted);
    const cases = [_]struct { name: []const u8, offset: ?usize = null, length: ?usize = null, password: []const u8 = "password", expected: anyerror }{
        .{ .name = "wrong password", .password = "wrong", .expected = error.AuthenticationFailed },
        .{ .name = "bad magic", .offset = 0, .expected = error.InvalidVault },
        .{ .name = "ciphertext", .offset = 64, .expected = error.AuthenticationFailed },
        .{ .name = "tag", .offset = encrypted.len - 1, .expected = error.AuthenticationFailed },
        .{ .name = "empty file", .length = 0, .expected = error.InvalidVault },
        .{ .name = "short header", .length = 63, .expected = error.InvalidVault },
        .{ .name = "truncated tag", .length = encrypted.len - 1, .expected = error.InvalidVault },
    };
    for (cases) |case| {
        errdefer std.debug.print("corrupted file case: {s}\n", .{case.name});
        const bytes = try testing.allocator.dupe(u8, encrypted[0 .. case.length orelse encrypted.len]);
        defer testing.allocator.free(bytes);
        if (case.offset) |offset| bytes[offset] ^= 1;
        try tmp.dir.writeFile(testing.io, .{ .sub_path = "accounts", .data = bytes });
        try expectLoadError(tmp.dir, case.password, case.expected);
        const after = try tmp.dir.readFileAlloc(testing.io, "accounts", testing.allocator, .limited(1024));
        defer testing.allocator.free(after);
        try testing.expectEqualSlices(u8, bytes, after);
        try expectDirectoryContents(tmp.dir, "accounts");
    }
    // Authentication can succeed while the decrypted account format is invalid.
    const invalid_database = try vault.seal(testing.allocator, testing.io, "password", "not a database", test_options);
    defer testing.allocator.free(invalid_database);
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "accounts", .data = invalid_database });
    try expectLoadError(tmp.dir, "password", error.InvalidFormat);
}
