const std = @import("std");
const vaxis = @import("vaxis");
const widgets = vaxis.widgets;

pub fn run(al: std.mem.Allocator, io: std.Io, env: *std.process.Environ.Map) !void {
    // Initialize a tty
    var buffer: [1024]u8 = undefined;
    var tty = try vaxis.Tty.init(io, &buffer);
    defer tty.deinit();

    // Initialize Vaxis
    var vx = try vaxis.init(io, al, env, .{});
    defer vx.deinit(al, tty.writer());

    // Start the read loop. This puts the terminal in raw mode and begins reading user input
    var loop: vaxis.Loop(Event) = .init(io, &tty, &vx);
    try loop.installResizeHandler();
    defer loop.uninstallResizeHandler();
    try loop.start();
    defer loop.stop();

    try vx.enterAltScreen(tty.writer());

    // Sends queries to terminal to detect certain features
    try vx.queryTerminal(tty.writer(), .fromSeconds(1));

    var text_view = widgets.TextView{};
    var text_view_buffer = widgets.TextView.Buffer{};
    defer text_view_buffer.deinit(al);
    try text_view_buffer.append(al, .{ .bytes = "'q' to close" });

    var status_text_view = widgets.TextView{};
    var status_text_view_buffer = widgets.TextView.Buffer{};
    defer status_text_view_buffer.deinit(al);
    var has_error_msg = false;

    while (true) {
        // nextEvent blocks until an event is in the queue
        const event = try loop.nextEvent();

        switch (event) {
            .key_press => |key| {
                if (key.matches('q', .{})) {
                    break;
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

        const win = vx.window();
        win.clear();

        text_view.draw(win, text_view_buffer);
        if (has_error_msg and win.height > 0) {
            const status_win = win.child(.{
                .x_off = 0,
                .y_off = win.height - 1,
                .width = win.width,
                .height = 1,
            });
            status_text_view.draw(status_win, status_text_view_buffer);
        }

        // Render the screen. Using a buffered writer will offer much better
        // performance, but is not required
        try vx.render(tty.writer());
    }
}

const Event = union(enum) {
    key_press: vaxis.Key,
    winsize: vaxis.Winsize,
};
