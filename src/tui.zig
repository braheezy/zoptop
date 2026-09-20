const std = @import("std");
const vaxis = @import("vaxis");
const widgets = vaxis.widgets;
const totp = @import("totp");
const draw = @import("ui/draw.zig");
const Layout = @import("ui/layout.zig");
const Navigation = @import("ui/navigation.zig").Navigation;
const rows = @import("ui/rows.zig");

pub fn run(al: std.mem.Allocator, io: std.Io, env: *std.process.Environ.Map) !void {
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

    var status_text_view = widgets.TextView{};
    var status_text_view_buffer = widgets.TextView.Buffer{};
    defer status_text_view_buffer.deinit(al);
    var has_error_msg = false;
    var dirty = true;
    var last_second: ?i64 = null;

    var nav: Navigation = .{};

    const normal_style: vaxis.Style = .{};

    main_loop: while (true) {
        for (0..64) |_| {
            const event = try loop.tryEvent() orelse break;

            switch (event) {
                .key_press => |key| {
                    if (key.matches('q', .{})) {
                        break :main_loop;
                    } else if (key.matches('e', .{})) {
                        status_text_view_buffer.clear(al);
                        try status_text_view_buffer.append(al, .{ .bytes = "sample error" });
                        try status_text_view_buffer.updateStyle(al, .{
                            .begin = 0,
                            .end = status_text_view_buffer.content.items.len,
                            .style = .{
                                .fg = .{ .index = 3 },
                            },
                        });
                        has_error_msg = true;
                    }
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
                nav.normalize(fixture_results.len, lay.list.height);

                const title_win = draw.subwindow(win, lay.title);
                draw.line(title_win, "zoptop", normal_style);

                const list_win = draw.subwindow(win, lay.list);
                try draw.drawAccountList(
                    arena,
                    list_win,
                    &fixture_accounts,
                    &fixture_results,
                    nav,
                    now,
                );

                const help_win = draw.subwindow(win, lay.help);
                draw.line(help_win, "j/k: move  q: quit", normal_style);

                if (has_error_msg and win.height > 0) {
                    const status_win = win.child(.{
                        .x_off = 0,
                        .y_off = win.height - 1,
                        .width = win.width,
                        .height = 1,
                    });
                    status_text_view.draw(status_win, status_text_view_buffer);
                }
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
