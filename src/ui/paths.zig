const std = @import("std");

pub fn resolve(al: std.mem.Allocator, io: std.Io, env: *const std.process.Environ.Map) ![]u8 {
    if (env.get("XDG_DATA_HOME")) |data_home| {
        return std.fmt.allocPrint(al, "{s}/.zoptop", .{data_home});
    } else if (env.get("HOME")) |home| {
        const config_home = try std.fmt.allocPrint(al, "{s}/.config", .{home});
        defer al.free(config_home);

        if (std.Io.Dir.openDirAbsolute(io, config_home, .{})) |config_dir| {
            config_dir.close(io);
            return std.fmt.allocPrint(al, "{s}/zoptop", .{config_home});
        } else |_| {}

        return std.fmt.allocPrint(al, "{s}/.zoptop", .{home});
    } else {
        var buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
        const len = try std.Io.Dir.cwd().realPath(io, &buffer);
        const cwd = buffer[0..len];

        return std.fs.path.join(al, &.{ cwd, ".zoptop" });
    }
}
