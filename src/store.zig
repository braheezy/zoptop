const std = @import("std");
const Account = @import("Account.zig");
const vault = @import("vault.zig");
const format = @import("format.zig");

pub fn save(
    al: std.mem.Allocator,
    io: std.Io,
    dir: std.Io.Dir,
    filename: []const u8,
    password: []const u8,
    accounts: []const Account,
    options: vault.SealOptions,
) !void {
    if (filename.len == 0 or
        !std.unicode.utf8ValidateSlice(filename) or
        std.mem.eql(u8, filename, ".") or
        std.mem.eql(u8, filename, "..") or
        std.mem.eql(u8, filename, "/") or
        std.mem.eql(u8, filename, "\\")) return error.InvalidFile;

    const plaintext = try format.encode(al, accounts);
    defer {
        std.crypto.secureZero(u8, plaintext);
        al.free(plaintext);
    }
    const encrypted_bytes = try vault.seal(al, io, password, plaintext, options);
    defer al.free(encrypted_bytes);

    var atomic_file = try dir.createFileAtomic(
        io,
        filename,
        .{ .replace = true, .permissions = .fromMode(0o600) },
    );
    defer atomic_file.deinit(io);

    try atomic_file.file.writeStreamingAll(io, encrypted_bytes);
    try atomic_file.file.sync(io);
    try atomic_file.replace(io);
}

pub fn load(
    al: std.mem.Allocator,
    io: std.Io,
    dir: std.Io.Dir,
    filename: []const u8,
    password: []const u8,
) !format.Database {
    if (filename.len == 0 or
        !std.unicode.utf8ValidateSlice(filename) or
        std.mem.eql(u8, filename, ".") or
        std.mem.eql(u8, filename, "..") or
        std.mem.eql(u8, filename, "/") or
        std.mem.eql(u8, filename, "\\")) return error.InvalidFile;

    const encrypted_bytes = try dir.readFileAlloc(io, filename, al, .limited(4 * 1024 * 1024));
    defer al.free(encrypted_bytes);
    const plaintext = try vault.open(al, io, password, encrypted_bytes);
    defer al.free(plaintext);
    return try format.decode(al, plaintext);
}
