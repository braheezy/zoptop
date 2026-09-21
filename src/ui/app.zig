const std = @import("std");
const vaxis = @import("vaxis");
const Navigation = @import("navigation.zig").Navigation;
const Session = @import("session.zig");
const Status = @import("status.zig").Status;
const SecretInput = @import("sercret_input.zig").SecretInput;

pub const Screen = enum {
    unlock,
    create_password,
    create_confirm,
    accounts,
    search,
    add_uri,
    confirm_delete,
};

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

pub fn init(io: std.Io, dir: std.Io.Dir) !App {
    var session: Session = .{ .dir = dir };

    const vault_exists = try session.exists(io);

    const screen: Screen = if (vault_exists)
        .unlock
    else
        .create_password;

    return .{
        .session = session,
        .screen = screen,
    };
}

pub fn handleKey(
    self: *App,
    al: std.mem.Allocator,
    io: std.Io,
    key: vaxis.Key,
    visible_rows: usize,
) !void {
    _ = io;
    _ = visible_rows;

    if (key.matches('q', .{})) {
        self.quit = true;
        return;
    }

    if (key.matches('e', .{})) {
        try self.status.set("sample error", .err);
        self.dirty = true;
    }

    _ = al;
}

// pub fn deinit(self: *App, al: std.mem.Allocator) void {}
