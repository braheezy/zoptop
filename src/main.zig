const std = @import("std");
const tui = @import("tui.zig");

pub fn main(init: std.process.Init) !void {
    const gpa: std.mem.Allocator = init.gpa;
    const io = init.io;

    const dir = std.Io.Dir.cwd();

    try tui.run(gpa, io, init.environ_map, dir);
}

test {
    std.testing.refAllDecls(@This());
}
