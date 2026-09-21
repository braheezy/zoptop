const std = @import("std");
const vaxis = @import("vaxis");
const Navigation = @import("navigation.zig").Navigation;
const Session = @import("session.zig");
const Status = @import("status.zig").Status;
const Kind = @import("status.zig").Kind;
const SecretInput = @import("sercret_input.zig").SecretInput;
const filter = @import("filter.zig");
const totp = @import("totp");
const draw = @import("draw.zig");
const Layout = @import("layout.zig").Layout;

pub const Screen = enum {
    unlock,
    create_password,
    create_confirm,
    accounts,
    search,
    add_uri,
    confirm_delete,
};

const normal_style: vaxis.Style = .{};

const App = @This();

screen: Screen = .unlock,
nav: Navigation = .{},
results: std.ArrayList(usize) = .empty,
session: Session,
status: Status = .{},
quit: bool = false,
dirty: bool = true,
pasting: bool = false,
password_input: SecretInput(1024) = .{},
confirmation_input: SecretInput(1024) = .{},
uri_input: SecretInput(16384) = .{},
search_input: SecretInput(256) = .{},
seal_options: totp.vault.SealOptions = .{ .params = .{} },

pub fn init(al: std.mem.Allocator, io: std.Io, dir: std.Io.Dir) !App {
    var session: Session = .{ .dir = dir };

    const screen: Screen = if (try session.exists(io))
        .unlock
    else
        .create_password;

    return .{
        .session = session,
        .screen = screen,
        .results = try std.ArrayList(usize).initCapacity(al, 1024),
    };
}

pub fn deinit(self: *App, al: std.mem.Allocator) void {
    self.password_input.clear();
    self.confirmation_input.clear();
    self.uri_input.clear();
    self.session.deinit(al);
    self.results.deinit(al);
}

pub fn handleKey(
    self: *App,
    al: std.mem.Allocator,
    io: std.Io,
    key: vaxis.Key,
    visible_rows: usize,
) !void {
    if (key.matches('q', .{})) {
        self.quit = true;
        self.touch();
        return;
    }

    switch (self.screen) {
        .unlock => try self.handleUnlockKey(al, io, key, visible_rows),

        .create_password => try self.handleCreatePasswordKey(key),

        .create_confirm => try self.handleCreateConfirmKey(al, io, key, visible_rows),

        .accounts => try self.handleAccountsKey(al, key, visible_rows),

        .search => try self.handleSearchKey(al, key, visible_rows),

        .add_uri => try self.handleAddUriKey(al, io, key, visible_rows),

        .confirm_delete => try self.handleConfirmDeleteKey(al, io, key, visible_rows),
    }
}

pub fn render(
    self: *App,
    arena: std.mem.Allocator,
    layout: Layout,
    win: vaxis.Window,
    now: i64,
) !void {
    const list_height: usize = @intCast(layout.list.height);
    self.nav.normalize(self.results.items.len, list_height);

    draw.line(draw.subwindow(win, layout.title), "zoptop", .{});
    try draw.drawAccountList(
        arena,
        draw.subwindow(win, layout.list),
        self.session.accounts(),
        self.results.items,
        self.nav,
        now,
    );

    self.drawPrompt(draw.subwindow(win, layout.prompt));
    // Draw the active help text in layout.help.
    draw.line(draw.subwindow(win, layout.status), self.status.slice(), statusStyle(self.status.kind));

    const help_win = draw.subwindow(win, layout.help);
    draw.line(help_win, "j/k: move  q: quit", .{});
}

pub fn drawPrompt(self: *App, prompt_win: vaxis.Window) void {
    switch (self.screen) {
        .unlock => {
            draw.line(prompt_win, "Unlock vault:", .{});

            var mask: [1024]u8 = undefined;
            @memset(mask[0..self.password_input.len], '*');

            draw.line(prompt_win, mask[0..self.password_input.len], .{});
        },
        .create_password => {
            draw.line(prompt_win, "Create password:", .{});

            var mask: [1024]u8 = undefined;
            @memset(mask[0..self.password_input.len], '*');

            draw.line(prompt_win, mask[0..self.password_input.len], .{});
        },
        .create_confirm => {
            draw.line(prompt_win, "Confirm password:", .{});

            var mask: [1024]u8 = undefined;
            @memset(mask[0..self.confirmation_input.len], '*');

            draw.line(prompt_win, mask[0..self.confirmation_input.len], .{});
        },
        .accounts => {},
        .search => {
            draw.line(prompt_win, "Search:", .{});
            draw.line(prompt_win, self.search_input.slice(), .{});
        },
        .add_uri => {
            draw.line(prompt_win, "Add account URI:", .{});
            draw.line(prompt_win, self.uri_input.slice(), .{});
        },
        .confirm_delete => {
            const result_position = self.nav.selected orelse return;
            const account_index = self.results.items[result_position];
            const account = self.session.accounts()[account_index];

            var text_buffer: [1024]u8 = undefined;

            const text = std.fmt.bufPrint(
                &text_buffer,
                "Delete account? {s} / {s}",
                .{ account.issuer, account.name },
            ) catch return;

            draw.line(prompt_win, "Delete account?", .{});
            draw.line(prompt_win, text, .{});
            draw.line(prompt_win, "Press Enter to delete, Escape to cancel", .{});
        },
    }
}

fn handleUnlockKey(
    self: *App,
    al: std.mem.Allocator,
    io: std.Io,
    key: vaxis.Key,
    visible_rows: usize,
) !void {
    if (key.matches(vaxis.Key.escape, .{})) {
        self.password_input.clear();
        self.status.clear();
        self.touch();
        return;
    }
    if (key.matches(vaxis.Key.backspace, .{})) {
        self.password_input.backspace();
        self.touch();
        return;
    }
    if (key.text) |text| {
        self.password_input.append(text) catch |err| {
            try self.showErrorFor(err);
            return;
        };
        self.status.clear();
        self.touch();
        return;
    }
    if (key.matches(vaxis.Key.enter, .{})) {
        self.session.unlock(al, io, self.password_input.slice()) catch |err| {
            self.password_input.clear();
            try self.showErrorFor(err);
            return;
        };
        filter.rebuild(al, &self.results, self.session.accounts(), "") catch |err| {
            try self.showErrorFor(err);
            return;
        };
        self.nav.normalize(self.results.items.len, visible_rows);
        self.password_input.clear();
        self.status.clear();
        self.screen = .accounts;
        self.touch();
    }
}

fn handleCreatePasswordKey(self: *App, key: vaxis.Key) !void {
    if (key.matches(vaxis.Key.escape, .{})) {
        self.password_input.clear();
        self.status.clear();
        self.touch();
        return;
    }

    if (key.matches(vaxis.Key.backspace, .{})) {
        self.password_input.backspace();
        self.touch();
        return;
    }

    if (key.text) |text| {
        self.password_input.append(text) catch |err| {
            try self.showErrorFor(err);
            return;
        };
        self.status.clear();
        self.touch();
        return;
    }

    if (!key.matches(vaxis.Key.enter, .{})) return;

    if (self.password_input.len == 0) {
        try self.showErrorFor(error.EmptyPassword);
        return;
    }

    self.confirmation_input.clear();
    self.status.clear();
    self.screen = .create_confirm;
    self.touch();
}

fn handleCreateConfirmKey(
    self: *App,
    al: std.mem.Allocator,
    io: std.Io,
    key: vaxis.Key,
    visible_rows: usize,
) !void {
    if (key.matches(vaxis.Key.escape, .{})) {
        self.confirmation_input.clear();
        self.status.clear();
        self.touch();
        return;
    }
    if (key.matches(vaxis.Key.backspace, .{})) {
        self.confirmation_input.backspace();
        self.touch();
        return;
    }
    if (key.text) |text| {
        self.confirmation_input.append(text) catch |err| {
            try self.showErrorFor(err);
            return;
        };
        self.status.clear();
        self.touch();
        return;
    }
    if (!key.matches(vaxis.Key.enter, .{})) return;

    if (!std.mem.eql(u8, self.confirmation_input.slice(), self.password_input.slice())) {
        self.confirmation_input.clear();
        try self.showError("Passwords do not match");
        return;
    }

    self.session.create(al, io, self.password_input.slice(), self.seal_options) catch |err| {
        try self.showErrorFor(err);
        return;
    };
    filter.rebuild(al, &self.results, self.session.accounts(), "") catch |err| {
        try self.showErrorFor(err);
        return;
    };
    self.nav.normalize(self.results.items.len, visible_rows);
    self.password_input.clear();
    self.confirmation_input.clear();
    self.status.clear();
    self.screen = .accounts;
    self.touch();
}

fn handleAccountsKey(
    self: *App,
    al: std.mem.Allocator,
    key: vaxis.Key,
    visible_rows: usize,
) !void {
    if (key.matches(vaxis.Key.down, .{}) or key.matches('j', .{})) {
        self.nav.move(.down, self.results.items.len, visible_rows);
        self.touch();
        return;
    }
    if (key.matches(vaxis.Key.up, .{}) or key.matches('k', .{})) {
        self.nav.move(.up, self.results.items.len, visible_rows);
        self.touch();
        return;
    }
    if (key.matches('l', .{})) {
        self.session.lock(al);
        self.password_input.clear();
        self.confirmation_input.clear();
        self.uri_input.clear();
        self.results.clearRetainingCapacity();
        self.nav.clear();
        self.status.clear();
        self.screen = .unlock;
        self.touch();
        return;
    }
    if (key.matches('a', .{})) {
        self.uri_input.clear();
        self.screen = .add_uri;
        self.touch();
        return;
    }
    if (key.matches('/', .{})) {
        self.search_input.clear();
        self.screen = .search;
        self.touch();
        return;
    }
    if (key.matches('d', .{})) {
        if (self.nav.selected) |_| {
            self.screen = .confirm_delete;
            self.touch();
        }
        return;
    }
    if (key.matches('c', .{})) {
        self.status.set("Copy is unavailable", .info) catch |err| {
            try self.showErrorFor(err);
            return;
        };
        self.touch();
        return;
    }
}

fn handleSearchKey(
    self: *App,
    al: std.mem.Allocator,
    key: vaxis.Key,
    visible_rows: usize,
) !void {
    if (key.matches(vaxis.Key.escape, .{})) {
        self.search_input.clear();

        try filter.rebuild(
            al,
            &self.results,
            self.session.accounts(),
            "",
        );

        self.nav.normalize(self.results.items.len, visible_rows);
        self.screen = .accounts;
        self.status.clear();
        self.touch();
        return;
    }

    if (key.matches(vaxis.Key.backspace, .{})) {
        self.search_input.backspace();
    } else if (key.text) |text| {
        self.search_input.append(text) catch |err| {
            try self.showErrorFor(err);
            return;
        };
    } else if (key.matches(vaxis.Key.enter, .{})) {
        self.screen = .accounts;
        self.touch();
        return;
    } else {
        return;
    }

    try filter.rebuild(
        al,
        &self.results,
        self.session.accounts(),
        self.search_input.slice(),
    );

    self.nav.normalize(self.results.items.len, visible_rows);
    self.touch();
}

fn handleAddUriKey(
    self: *App,
    al: std.mem.Allocator,
    io: std.Io,
    key: vaxis.Key,
    visible_rows: usize,
) !void {
    if (key.matches(vaxis.Key.escape, .{})) {
        self.uri_input.clear();
        self.status.clear();
        self.screen = .accounts;
        self.touch();
        return;
    }

    if (key.matches(vaxis.Key.backspace, .{})) {
        self.uri_input.backspace();
        self.touch();
        return;
    }

    if (key.text) |text| {
        try self.uri_input.append(text);
        self.touch();
        return;
    }

    if (!key.matches(vaxis.Key.enter, .{})) return;

    const new_account = try totp.otpauth.parse(al, self.uri_input.slice());
    defer new_account.deinit(al);

    var temp_accounts = try cloneAccountsWithExtra(
        al,
        self.session.accounts(),
        new_account,
    );
    errdefer temp_accounts.deinit(al);

    try totp.store.save(
        al,
        io,
        self.session.dir,
        "accounts",
        self.session.password.slice(),
        temp_accounts.items,
        self.seal_options,
    );

    const replacement = try temp_accounts.toOwnedSlice(al);
    replaceDatabase(self, al, replacement);
    self.uri_input.clear();
    try filter.rebuild(al, &self.results, self.session.accounts(), "");
    self.nav.selected = self.results.items.len - 1;
    self.nav.normalize(self.results.items.len, visible_rows);
    self.screen = .accounts;
    self.touch();
}

fn handleConfirmDeleteKey(
    self: *App,
    al: std.mem.Allocator,
    io: std.Io,
    key: vaxis.Key,
    visible_rows: usize,
) !void {
    if (key.matches(vaxis.Key.escape, .{})) {
        self.screen = .accounts;
        self.status.clear();
        self.touch();
        return;
    }
    if (key.matches(vaxis.Key.enter, .{})) {
        const selected_result = self.nav.selected orelse {
            self.screen = .accounts;
            self.touch();
            return;
        };

        const account_index = self.results.items[selected_result];
        var temp_accounts = try cloneAccountsWithoutIndex(
            al,
            self.session.accounts(),
            account_index,
        );
        errdefer deinitAccountList(al, &temp_accounts);

        totp.store.save(
            al,
            io,
            self.session.dir,
            Session.filename,
            self.session.password.slice(),
            temp_accounts.items,
            self.seal_options,
        ) catch |err| {
            try self.showErrorFor(err);
            self.screen = .accounts;
            return;
        };

        const replacement = try temp_accounts.toOwnedSlice(al);
        self.replaceDatabase(al, replacement);
        try filter.rebuild(al, &self.results, self.session.accounts(), "");
        self.nav.normalize(self.results.items.len, visible_rows);
        self.screen = .accounts;
        self.touch();
    }
}

fn replaceDatabase(self: *App, al: std.mem.Allocator, replacement: []totp.Account) void {
    const new_database = totp.format.Database{ .accounts = replacement };
    if (self.session.database) |old_database| old_database.deinit(al);
    self.session.database = new_database;
}

fn cloneAccount(al: std.mem.Allocator, source: totp.Account) !totp.Account {
    const issuer = try al.dupe(u8, source.issuer);
    errdefer al.free(issuer);

    const name = try al.dupe(u8, source.name);
    errdefer al.free(name);

    const secret = try al.dupe(u8, source.secret);
    errdefer {
        std.crypto.secureZero(u8, secret);
        al.free(secret);
    }

    return .{
        .issuer = issuer,
        .name = name,
        .secret = secret,
        .digits = source.digits,
        .period = source.period,
        .algorithm = source.algorithm,
    };
}

fn cloneAccountsWithExtra(al: std.mem.Allocator, current: []const totp.Account, extra: totp.Account) !std.ArrayList(totp.Account) {
    var accounts: std.ArrayList(totp.Account) = .empty;

    errdefer {
        for (accounts.items) |account| {
            account.deinit(al);
        }
        accounts.deinit(al);
    }

    try accounts.ensureTotalCapacity(al, current.len + 1);

    for (current) |account| {
        const copy = try cloneAccount(al, account);

        accounts.appendAssumeCapacity(copy);
    }

    const extra_copy = try cloneAccount(al, extra);
    accounts.appendAssumeCapacity(extra_copy);

    return accounts;
}

fn cloneAccountsWithoutIndex(al: std.mem.Allocator, current: []const totp.Account, omitted_index: usize) !std.ArrayList(totp.Account) {
    var copied: std.ArrayList(totp.Account) = .empty;

    errdefer {
        for (copied.items) |account| {
            account.deinit(al);
        }
        copied.deinit(al);
    }

    try copied.ensureTotalCapacity(al, current.len);

    for (current, 0..) |account, index| {
        if (index == omitted_index) continue;

        const copy = try cloneAccount(al, account);
        copied.appendAssumeCapacity(copy);
    }

    return copied;
}

fn deinitAccountList(al: std.mem.Allocator, accounts: *std.ArrayList(totp.Account)) void {
    for (accounts.items) |account| {
        account.deinit(al);
    }

    accounts.deinit(al);
}

fn statusStyle(kind: Kind) vaxis.Style {
    return switch (kind) {
        .info => .{},
        .err => .{
            .fg = .{ .index = 1 },
        },
    };
}

fn touch(self: *App) void {
    self.dirty = true;
}

fn showError(self: *App, message: []const u8) !void {
    try self.status.set(message, .err);
    self.dirty = true;
}

fn showErrorFor(self: *App, err: anyerror) !void {
    const message: []const u8 = switch (err) {
        error.AuthenticationFailed => "Wrong password",
        error.InvalidVault => "Invalid vault",
        error.InvalidUri => "Invalid URI",
        error.FileNotFound => "Vault not found",
        error.AlreadyUnlocked => "Already unlocked",
        error.EmptyPassword => "Password cannot be empty",
        error.InputTooLong => "Input is too long",
        error.MessageTooLong => "Status message is too long",
        else => "Operation failed",
    };
    try self.showError(message);
}

const testing = std.testing;
const test_seal_options: totp.vault.SealOptions = .{ .params = .{ .t = 1, .m = 32, .p = 1 } };
const test_visible_rows = 5;

fn press(app: *App, key: vaxis.Key) !void {
    try app.handleKey(testing.allocator, testing.io, key, test_visible_rows);
}

fn typeText(app: *App, text: []const u8) !void {
    for (text, 0..) |byte, index| {
        try press(app, .{
            .codepoint = byte,
            .text = text[index .. index + 1],
        });
    }
}

fn initializeTestApp(dir: std.Io.Dir) !App {
    var app = try App.init(testing.allocator, testing.io, dir);
    app.seal_options = test_seal_options;
    return app;
}

fn createTestVault(dir: std.Io.Dir, password: []const u8) !void {
    var session: Session = .{ .dir = dir };
    defer session.deinit(testing.allocator);
    try session.create(testing.allocator, testing.io, password, test_seal_options);
}

test "app starts on create password for a missing vault" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var app = try initializeTestApp(tmp.dir);
    defer app.deinit(testing.allocator);

    try testing.expectEqual(Screen.create_password, app.screen);
}

test "app starts on unlock for an existing vault" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try createTestVault(tmp.dir, "pass");

    var app = try initializeTestApp(tmp.dir);
    defer app.deinit(testing.allocator);

    try testing.expectEqual(Screen.unlock, app.screen);
}

test "app quits when q is pressed" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var app = try initializeTestApp(tmp.dir);
    defer app.deinit(testing.allocator);
    app.dirty = false;

    try press(&app, .{ .codepoint = 'q' });
    try testing.expect(app.quit);
    try testing.expect(app.dirty);
}

test "app creates a vault after matching password confirmation" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var app = try initializeTestApp(tmp.dir);
    defer app.deinit(testing.allocator);

    try typeText(&app, "pass");
    try press(&app, .{ .codepoint = vaxis.Key.enter });
    try testing.expectEqual(Screen.create_confirm, app.screen);

    try typeText(&app, "mismatch");
    try press(&app, .{ .codepoint = vaxis.Key.enter });
    try testing.expectEqual(Screen.create_confirm, app.screen);
    try testing.expectEqualStrings("Passwords do not match", app.status.slice());
    try testing.expectEqual(@as(usize, 0), app.confirmation_input.len);

    try typeText(&app, "pass");
    try press(&app, .{ .codepoint = vaxis.Key.enter });
    try testing.expectEqual(Screen.accounts, app.screen);
    try testing.expect(app.session.database != null);
    try testing.expectEqual(@as(usize, 0), app.results.items.len);
}

test "app stays on unlock for a wrong password and unlocks with the right password" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try createTestVault(tmp.dir, "pass");

    var app = try initializeTestApp(tmp.dir);
    defer app.deinit(testing.allocator);

    try typeText(&app, "wrong");
    try press(&app, .{ .codepoint = vaxis.Key.enter });
    try testing.expectEqual(Screen.unlock, app.screen);
    try testing.expectEqualStrings("Wrong password", app.status.slice());
    try testing.expectEqual(@as(usize, 0), app.password_input.len);
    try testing.expect(app.session.database == null);

    try typeText(&app, "pass");
    try press(&app, .{ .codepoint = vaxis.Key.enter });
    try testing.expectEqual(Screen.accounts, app.screen);
    try testing.expect(app.session.database != null);
    try testing.expectEqual(@as(usize, 0), app.results.items.len);
}

test "app navigation does not wrap" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var app = try initializeTestApp(tmp.dir);
    defer app.deinit(testing.allocator);
    app.screen = .accounts;
    try app.results.append(testing.allocator, 0);
    try app.results.append(testing.allocator, 1);
    try app.results.append(testing.allocator, 2);

    try press(&app, .{ .codepoint = vaxis.Key.up });
    try testing.expectEqual(@as(?usize, 0), app.nav.selected);

    for (0..10) |_| try press(&app, .{ .codepoint = 'j' });
    try testing.expectEqual(@as(?usize, 2), app.nav.selected);

    for (0..10) |_| try press(&app, .{ .codepoint = 'k' });
    try testing.expectEqual(@as(?usize, 0), app.nav.selected);
}

test "app lock clears state and permits a later unlock" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try createTestVault(tmp.dir, "pass");

    var app = try initializeTestApp(tmp.dir);
    defer app.deinit(testing.allocator);

    try typeText(&app, "pass");
    try press(&app, .{ .codepoint = vaxis.Key.enter });
    try testing.expectEqual(Screen.accounts, app.screen);

    try app.confirmation_input.append("confirm");
    try app.uri_input.append("otpauth://totp/example?secret=ABC");
    try app.results.append(testing.allocator, 0);
    app.nav.normalize(app.results.items.len, test_visible_rows);

    try press(&app, .{ .codepoint = 'l' });
    try testing.expectEqual(Screen.unlock, app.screen);
    try testing.expect(app.session.database == null);
    try testing.expectEqualStrings("", app.session.password.slice());
    try testing.expectEqual(@as(usize, 0), app.results.items.len);
    try testing.expectEqual(@as(?usize, null), app.nav.selected);
    try testing.expectEqual(@as(usize, 0), app.password_input.len);
    try testing.expectEqual(@as(usize, 0), app.confirmation_input.len);
    try testing.expectEqual(@as(usize, 0), app.uri_input.len);

    try typeText(&app, "pass");
    try press(&app, .{ .codepoint = vaxis.Key.enter });
    try testing.expectEqual(Screen.accounts, app.screen);
    try testing.expect(app.session.database != null);
}
