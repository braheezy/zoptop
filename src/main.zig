const std = @import("std");
const tui = @import("tui.zig");
const paths = @import("ui/paths.zig");

pub fn main(init: std.process.Init) !void {
    const gpa: std.mem.Allocator = init.gpa;
    const io = init.io;

    const path = try paths.resolve(gpa, io, init.environ_map);
    defer gpa.free(path);

    try std.Io.Dir.cwd().createDirPath(io, path);
    const dir = try std.Io.Dir.openDirAbsolute(io, path, .{});
    defer dir.close(io);

    try tui.run(gpa, io, init.environ_map, dir);
}

test {
    std.testing.refAllDecls(@This());
}
