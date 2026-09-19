const std = @import("std");
const tui = @import("tui.zig");

pub fn main(init: std.process.Init) !void {
    const arena: std.mem.Allocator = init.arena.allocator();
    const io = init.io;

    try tui.run(arena, io, init.environ_map);
}
