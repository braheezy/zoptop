const std = @import("std");
const vaxis = @import("vaxis");
const widgets = vaxis.widgets;
const totp = @import("totp");
const draw = @import("ui/draw.zig");
const Layout = @import("ui/layout.zig");
const Navigation = @import("ui/navigation.zig").Navigation;
const rows = @import("ui/rows.zig");
const App = @import("ui/app.zig");

const session = @import("ui/session.zig");

pub fn run(
    al: std.mem.Allocator,
    io: std.Io,
    env: *std.process.Environ.Map,
    dir: std.Io.Dir,
) !void {
    var ar = std.heap.ArenaAllocator.init(al);
    const arena = ar.allocator();
    defer ar.deinit();

    // Initialize a tty
    var buffer: [1024]u8 = undefined;
    var tty = try vaxis.Tty.init(io, &buffer);
    defer tty.deinit();

    // Initialize Vaxis
    var vx = try vaxis.init(io, al, env, .{});
    defer vx.deinit(al, tty.writer());

    const fixture_accounts = [_]totp.Account{
        .{ .issuer = "Example", .name = "alice@example.com", .secret = "12345678901234567890" },
        .{ .issuer = "Work", .name = "alice", .secret = "12345678901234567890", .digits = 8 },
        .{ .issuer = "Other", .name = "café", .secret = "12345678901234567890", .period = 60 },
    };
    const fixture_results = [_]usize{ 0, 1, 2 };

    // Start the read loop. This puts the terminal in raw mode and begins reading user input
    var loop: vaxis.Loop(Event) = .init(io, &tty, &vx);
    try loop.installResizeHandler();
    defer loop.uninstallResizeHandler();
    try loop.start();
    defer loop.stop();

    try vx.enterAltScreen(tty.writer());

    // Sends queries to terminal to detect certain features
    try vx.queryTerminal(tty.writer(), .fromSeconds(1));

    var dirty = true;
    var last_second: ?i64 = null;

    var app = try App.init(al, io, dir);
    defer app.deinit(al);

    const normal_style: vaxis.Style = .{};

    main_loop: while (true) {
        for (0..64) |_| {
            const event = try loop.tryEvent() orelse break;

            switch (event) {
                .key_press => |key| {
                    const list_height: usize = if (Layout.calculate(
                        vx.window().width,
                        vx.window().height,
                    )) |current_layout|
                        @intCast(current_layout.list.height)
                    else
                        0;

                    try app.handleKey(al, io, key, list_height);

                    if (app.quit)
                        break :main_loop;
                },

                .winsize => |ws| try vx.resize(al, tty.writer(), ws),
            }

            dirty = true;
        }

        const now = std.Io.Timestamp.now(io, .real).toSeconds();
        if (last_second == null or now != last_second.?) {
            last_second = now;
            dirty = true;
        }

        if (dirty) {
            const win = vx.window();
            win.clear();
            win.hideCursor();

            const layout = Layout.calculate(win.width, win.height);
            if (layout) |lay| {
                app.nav.normalize(fixture_results.len, lay.list.height);

                const title_win = draw.subwindow(win, lay.title);
                draw.line(title_win, "zoptop", normal_style);

                const list_win = draw.subwindow(win, lay.list);
                try draw.drawAccountList(
                    arena,
                    list_win,
                    &fixture_accounts,
                    &fixture_results,
                    app.nav,
                    now,
                );

                const help_win = draw.subwindow(win, lay.help);
                draw.line(help_win, "j/k: move  q: quit", normal_style);
            } else {
                draw.line(win, "Make the terminal larger", normal_style);
            }

            // Render the screen. Using a buffered writer will offer much better
            // performance, but is not required
            try vx.render(tty.writer());
            try tty.writer().flush();

            _ = ar.reset(.retain_capacity);
            dirty = false;
        }

        try std.Io.sleep(io, .fromMilliseconds(25), .awake);
    }
}

const Event = union(enum) {
    key_press: vaxis.Key,
    winsize: vaxis.Winsize,
};
