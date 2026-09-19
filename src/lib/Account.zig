const std = @import("std");
const Allocator = std.mem.Allocator;
pub const Totp = @import("totp.zig").Totp;
const Algorithm = @import("algorithm.zig").Algorithm;

pub const Account = @This();
issuer: []const u8,
name: []const u8,
secret: []const u8,
digits: u8 = 6,
period: u32 = 30,
algorithm: Algorithm = .sha1,

pub fn deinit(self: Account, allocator: Allocator) void {
    allocator.free(self.issuer);
    allocator.free(self.name);
    allocator.free(self.secret);
}

pub fn generator(self: Account) Totp {
    return .{
        .secret = self.secret,
        .digits = self.digits,
        .period = self.period,
        .algorithm = self.algorithm,
    };
}
