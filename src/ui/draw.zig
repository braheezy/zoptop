const std = @import("std");
const vaxis = @import("vaxis");
const widgets = vaxis.widgets;
const layout = @import("layout.zig");
const Navigation = @import("navigation.zig").Navigation;
const totp = @import("totp");
const rows = @import("rows.zig");

pub fn subwindow(parent: vaxis.Window, rect: layout.Rect) vaxis.Window {
    return parent.child(.{
        .x_off = rect.x,
        .y_off = rect.y,
        .width = rect.width,
        .height = rect.height,
    });
}

pub fn line(win: vaxis.Window, text: []const u8, style: vaxis.Style) void {
    if (win.height == 0 or win.width == 0) return;

    _ = win.printSegment(.{ .text = text, .style = style }, .{ .wrap = .none });
}

pub fn drawAccountRow(
    win: vaxis.Window,
    account: totp.Account,
    code: []const u8,
    remaining: []const u8,
    selected: bool,
) void {
    const cols = layout.columns(win.width) orelse return;
    const row_style: vaxis.Style = if (selected)
        .{ .fg = .{ .index = 0 }, .bg = .{ .index = 7 } }
    else
        .{};
    win.fill((.{ .char = .{ .grapheme = " " }, .style = row_style }));

    line(subwindow(win, cols.marker), if (selected) ">" else " ", row_style);
    line(subwindow(win, cols.issuer), if (account.issuer.len == 0) "—" else account.issuer, row_style);
    line(subwindow(win, cols.name), account.name, row_style);
    line(subwindow(win, cols.code), code, row_style);
    line(subwindow(win, cols.remaining), remaining, row_style);
}

pub fn drawAccountList(
    al: std.mem.Allocator,
    win: vaxis.Window,
    accounts: []const totp.Account,
    results: []const usize,
    nav: Navigation,
    timestamp: i64,
) !void {
    if (accounts.len == 0) {
        line(win, "No accounts yet. Press a to add one.", .{});
        return;
    }
    if (results.len == 0) {
        line(win, "No matches.", .{});
        return;
    }

    const available = results.len - nav.first_visible;
    const visible = @min(available, win.height);
    for (0..visible) |screen_row| {
        const result_index = nav.first_visible + screen_row;
        const account_index = results[result_index];
        const row_window = win.child(.{ .y_off = @intCast(screen_row), .width = win.width, .height = 1 });

        const account = accounts[account_index];

        if (rows.build(account, timestamp)) |text| {
            const code = try al.dupe(u8, text.code[0..text.code_len]);
            const remaining = try al.dupe(u8, text.remaining[0..text.remaining_len]);

            drawAccountRow(row_window, account, code, remaining, nav.selected == result_index);
        } else |_| {
            drawAccountRow(row_window, account, "ERROR", "", nav.selected == result_index);
        }
    }
}
