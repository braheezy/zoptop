pub const Rect = struct { x: u16, y: u16, width: u16, height: u16 };
pub const Layout = struct {
    title: Rect,
    list: Rect,
    prompt: Rect,
    help: Rect,
    status: Rect,
};
pub const Columns = struct {
    marker: Rect,
    issuer: Rect,
    name: Rect,
    code: Rect,
    remaining: Rect,
};

pub fn calculate(width: u16, height: u16) ?Layout {
    if (width < 40 or height < 7) return null;
    return .{
        .title = .{ .x = 0, .y = 0, .width = width, .height = 1 },
        .list = .{ .x = 0, .y = 2, .width = width, .height = height - 5 },
        .prompt = .{ .x = 0, .y = height - 3, .width = width, .height = 1 },
        .help = .{ .x = 0, .y = height - 2, .width = width, .height = 1 },
        .status = .{ .x = 0, .y = height - 1, .width = width, .height = 1 },
    };
}

pub fn columns(width: u16) ?Columns {
    if (width < 40) return null;

    return .{
        .marker = .{ .x = 0, .y = 0, .width = 2, .height = 1 },
        .issuer = .{ .x = 2, .y = 0, .width = 12, .height = 1 },
        .name = .{ .x = 15, .y = 0, .width = width - 32, .height = 1 },
        .code = .{ .x = width - 16, .y = 0, .width = 8, .height = 1 },
        .remaining = .{ .x = width - 7, .y = 0, .width = 7, .height = 1 },
    };
}

const testing = @import("std").testing;

test "layout reserves the footer and has no overlapping rows" {
    const actual = calculate(80, 24).?;
    try testing.expectEqual(@as(u16, 2), actual.list.y);
    try testing.expectEqual(@as(u16, 19), actual.list.height);
    try testing.expectEqual(@as(u16, 21), actual.prompt.y);
    try testing.expectEqual(@as(u16, 22), actual.help.y);
    try testing.expectEqual(@as(u16, 23), actual.status.y);
    try testing.expectEqual(actual.prompt.y, actual.list.y + actual.list.height);
    try testing.expect(calculate(39, 24) == null);
    try testing.expect(calculate(80, 6) == null);
    try testing.expect(calculate(0, 0) == null);
    try testing.expect(calculate(40, 7) != null);
}

test "columns leave eight cells for codes" {
    const actual = columns(80).?;
    try testing.expectEqual(@as(u16, 15), actual.name.x);
    try testing.expectEqual(@as(u16, 48), actual.name.width);
    try testing.expectEqual(@as(u16, 64), actual.code.x);
    try testing.expectEqual(@as(u16, 8), actual.code.width);
    try testing.expectEqual(@as(u16, 80), actual.remaining.x + actual.remaining.width);
    try testing.expect(columns(39) == null);
    for (40..201) |width| {
        const col = columns(@intCast(width)).?;
        try testing.expect(col.name.x + col.name.width < col.code.x);
        try testing.expect(col.code.x + col.code.width < col.remaining.x);
    }
}
