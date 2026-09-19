const std = @import("std");
const tui = @import("tui.zig");

pub fn main(init: std.process.Init) !void {
    const gpa: std.mem.Allocator = init.gpa;
    const io = init.io;

    try tui.run(gpa, io, init.environ_map);
}

test {
    std.testing.refAllDecls(@This());
}
