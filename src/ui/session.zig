const std = @import("std");
const totp = @import("totp");
const SecretInput = @import("sercret_input.zig").SecretInput;

pub const filename = "accounts";

pub const Session = @This();

dir: std.Io.Dir,
database: ?totp.format.Database = null,
password: SecretInput(1024) = .{},

pub fn exists(self: *const Session, io: std.Io) !bool {
    const stat = self.dir.statFile(io, filename, .{}) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => return err,
    };

    if (stat.kind == .directory)
        return error.IsDir;

    return true;
}

pub fn accounts(self: *const Session) []const totp.Account {
    if (self.database) |database| {
        return database.accounts;
    }

    return &.{};
}

pub fn unlock(
    self: *Session,
    al: std.mem.Allocator,
    io: std.Io,
    password: []const u8,
) !void {
    if (password.len == 0)
        return error.EmptyPassword;

    if (password.len > self.password.bytes.len)
        return error.InputTooLong;

    if (self.database) |_| {
        return error.AlreadyUnlocked;
    } else {
        if (password.len == 0) return error.EmptyPassword;
        if (password.len > 1024) return error.InputTooLong;

        const loaded = try totp.store.load(al, io, self.dir, filename, password);
        errdefer loaded.deinit(al);

        var new_password: SecretInput(1024) = .{};
        try new_password.append(password);

        self.password.clear();
        self.password = new_password;
        self.database = loaded;
    }
}

pub fn create(
    self: *Session,
    al: std.mem.Allocator,
    io: std.Io,
    password: []const u8,
    options: totp.vault.SealOptions,
) !void {
    if (self.database != null)
        return error.AlreadyUnlocked;

    if (password.len == 0)
        return error.EmptyPassword;

    if (password.len > self.password.bytes.len)
        return error.InputTooLong;

    if (try self.exists(io))
        return error.VaultAlreadyExists;

    const accts = try al.alloc(totp.Account, 0);

    var empty_db = totp.format.Database{
        .accounts = accts,
    };
    errdefer empty_db.deinit(al);

    // This writes the encrypted empty database to disk.
    try totp.store.save(
        al,
        io,
        self.dir,
        filename,
        password,
        empty_db.accounts,
        options,
    );

    // These operations happen only after saving succeeded.
    try self.password.append(password);
    self.database = empty_db;
}

pub fn lock(self: *Session, al: std.mem.Allocator) void {
    self.password.clear();
    if (self.database) |db| {
        self.database = null;
        db.deinit(al);
    }
}

pub fn deinit(self: *Session, al: std.mem.Allocator) void {
    self.lock(al);
}

const testing = std.testing;
const test_options: totp.vault.SealOptions = .{ .params = .{ .t = 1, .m = 32, .p = 1 } };

test "session reports whether its vault exists" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var session: Session = .{ .dir = tmp.dir };
    try testing.expect(!(try session.exists(testing.io)));

    try tmp.dir.writeFile(testing.io, .{ .sub_path = filename, .data = "not a vault" });
    try testing.expect(try session.exists(testing.io));
}

test "session create, lock, failed unlock, and successful unlock" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var session: Session = .{ .dir = tmp.dir };
    defer session.deinit(testing.allocator);

    try session.create(testing.allocator, testing.io, "correct password", test_options);
    try testing.expect(session.database != null);
    try testing.expectEqual(@as(usize, 0), session.accounts().len);
    try testing.expectEqualStrings("correct password", session.password.slice());

    session.lock(testing.allocator);
    try testing.expect(session.database == null);
    try testing.expectEqualStrings("", session.password.slice());

    try testing.expectError(
        error.AuthenticationFailed,
        session.unlock(testing.allocator, testing.io, "wrong password"),
    );
    try testing.expect(session.database == null);
    try testing.expectEqualStrings("", session.password.slice());

    try session.unlock(testing.allocator, testing.io, "correct password");
    try testing.expect(session.database != null);
    try testing.expectEqual(@as(usize, 0), session.accounts().len);
    try testing.expectEqualStrings("correct password", session.password.slice());
}

test "session lock is safe to call repeatedly" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var session: Session = .{ .dir = tmp.dir };
    defer session.deinit(testing.allocator);

    try session.create(testing.allocator, testing.io, "password", test_options);
    session.lock(testing.allocator);
    session.lock(testing.allocator);

    try testing.expect(session.database == null);
    try testing.expectEqualStrings("", session.password.slice());
}

test "session refuses to create over an existing vault" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var session: Session = .{ .dir = tmp.dir };
    defer session.deinit(testing.allocator);

    try tmp.dir.writeFile(testing.io, .{ .sub_path = filename, .data = "existing" });
    try testing.expectError(
        error.VaultAlreadyExists,
        session.create(testing.allocator, testing.io, "password", test_options),
    );
    try testing.expect(session.database == null);
    try testing.expectEqualStrings("", session.password.slice());
}

test "session rejects a directory named accounts" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.createDir(testing.io, filename, .default_dir);

    var session: Session = .{ .dir = tmp.dir };
    try testing.expectError(error.IsDir, session.exists(testing.io));
    try testing.expectError(
        error.IsDir,
        session.create(testing.allocator, testing.io, "password", test_options),
    );
    try testing.expect(session.database == null);
    try testing.expectEqualStrings("", session.password.slice());
}

test "failed create leaves the session locked" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const invalid_options: totp.vault.SealOptions = .{ .params = .{ .t = 1, .m = 7, .p = 1 } };
    var session: Session = .{ .dir = tmp.dir };
    defer session.deinit(testing.allocator);

    try testing.expectError(
        error.InvalidKdfParameters,
        session.create(testing.allocator, testing.io, "password", invalid_options),
    );
    try testing.expect(session.database == null);
    try testing.expectEqualStrings("", session.password.slice());
    try testing.expect(!(try session.exists(testing.io)));
}

test "empty unlock password leaves the session locked" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var session: Session = .{ .dir = tmp.dir };
    defer session.deinit(testing.allocator);

    try testing.expectError(
        error.EmptyPassword,
        session.unlock(testing.allocator, testing.io, ""),
    );
    try testing.expect(session.database == null);
    try testing.expectEqualStrings("", session.password.slice());
}

test "oversized unlock password leaves the session locked" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var session: Session = .{ .dir = tmp.dir };
    defer session.deinit(testing.allocator);

    const oversized = [_]u8{'x'} ** 1025;
    try testing.expectError(
        error.InputTooLong,
        session.unlock(testing.allocator, testing.io, &oversized),
    );
    try testing.expect(session.database == null);
    try testing.expectEqualStrings("", session.password.slice());
}
