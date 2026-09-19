pub const Direction = enum { up, down };
pub const Navigation = struct {
    selected: ?usize = null,
    first_visible: usize = 0,

    pub fn normalize(self: *Navigation, count: usize, visible_rows: usize) void {
        if (count == 0) {
            self.selected = null;
            self.first_visible = 0;
            return;
        }

        self.selected = @min(self.selected orelse 0, count - 1);

        if (visible_rows == 0) {
            self.first_visible = 0;
            return;
        }

        self.first_visible = count -| visible_rows;
        if (self.selected.? < self.first_visible) self.first_visible = self.selected.?;
        if (self.selected.? - self.first_visible >= visible_rows) {
            self.first_visible = self.selected.? - visible_rows + 1;
        }
    }
    pub fn move(self: *Navigation, direction: Direction, count: usize, visible_rows: usize) void {
        self.normalize(count, visible_rows);
        if (count == 0) return;

        switch (direction) {
            .up => {
                if (self.selected) |*sel| {
                    if (sel.* > 0) sel.* -= 1;
                }
            },
            .down => {
                if (self.selected) |*sel| {
                    if (sel.* < count - 1) sel.* += 1;
                }
            },
        }

        self.normalize(count, visible_rows);
    }
};

const testing = @import("std").testing;

test "navigation handles an empty list and zero height" {
    var nav: Navigation = .{};
    nav.move(.down, 0, 5);
    try testing.expectEqual(@as(?usize, null), nav.selected);
    try testing.expectEqual(@as(usize, 0), nav.first_visible);
    nav.normalize(3, 0);
    try testing.expectEqual(@as(?usize, 0), nav.selected);
    nav.move(.down, 3, 0);
    try testing.expectEqual(@as(?usize, 1), nav.selected);
    try testing.expectEqual(@as(usize, 0), nav.first_visible);
}

test "navigation scrolls without wrapping" {
    var nav: Navigation = .{};
    nav.normalize(5, 2);
    nav.move(.up, 5, 2);
    try testing.expectEqual(@as(?usize, 0), nav.selected);
    for (0..10) |_| nav.move(.down, 5, 2);
    try testing.expectEqual(@as(?usize, 4), nav.selected);
    try testing.expectEqual(@as(usize, 3), nav.first_visible);
    for (0..4) |_| nav.move(.up, 5, 2);
    try testing.expectEqual(@as(?usize, 0), nav.selected);
    try testing.expectEqual(@as(usize, 0), nav.first_visible);
}

test "navigation recovers after deletion and resize" {
    var nav: Navigation = .{ .selected = 4, .first_visible = 3 };
    nav.normalize(2, 1);
    try testing.expectEqual(@as(?usize, 1), nav.selected);
    try testing.expectEqual(@as(usize, 1), nav.first_visible);
    nav.normalize(2, 10);
    try testing.expectEqual(@as(usize, 0), nav.first_visible);
    nav.normalize(0, 10);
    try testing.expectEqual(@as(?usize, null), nav.selected);
}
