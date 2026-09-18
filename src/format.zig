const std = @import("std");
const Account = @import("Account.zig");

pub const Database = struct {
    accounts: []Account,

    pub fn deinit(self: Database, al: std.mem.Allocator) void {
        for (self.accounts) |acc| {
            acc.deinit(al);
        }
        al.free(self.accounts);
    }
};

pub fn encode(al: std.mem.Allocator, accounts: []const Account) ![]u8 {
    if (accounts.len > 4 * 1024) return error.TooManyAccounts;

    var size: usize = 10;

    for (accounts) |account| {
        if (account.secret.len > 4 * 1024) return error.InvalidAccount;
        if (account.issuer.len > 4 * 1024 * 4) return error.InvalidAccount;
        if (account.name.len > 4 * 1024 * 4) return error.InvalidAccount;

        size += 18 + account.issuer.len + account.name.len + account.secret.len;
    }
    if (size > 4 * 1024 * 1024) return error.InvalidAccount;

    const output = try al.alloc(u8, size);
    errdefer al.free(output);

    var i: usize = 0;
    @memcpy(output[i .. i + 4], "ZOTP");
    i += 4;

    var version_bytes: [2]u8 = undefined;
    std.mem.writeInt(u16, &version_bytes, 1, .big);
    @memcpy(output[i .. i + 2], &version_bytes);
    i += 2;

    var account_count_bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &account_count_bytes, @intCast(accounts.len), .big);
    @memcpy(output[i .. i + 4], &account_count_bytes);
    i += 4;

    for (accounts) |account| {
        var buf: [4]u8 = undefined;

        const algo: u8 = switch (account.algorithm) {
            .sha1 => 1,
            .sha256 => 2,
            .sha512 => 3,
        };
        std.mem.writeInt(u8, &buf[0], algo, .big);
        output[i] = buf[0];
        i += 1;

        std.mem.writeInt(u8, &buf[0], account.digits, .big);
        output[i] = buf[0];
        i += 1;

        if (account.period == 0) return error.InvalidAccount;
        std.mem.writeInt(u32, &buf, account.period, .big);
        @memcpy(output[i .. i + 4], &buf);
        i += 4;

        std.mem.writeInt(u32, &buf, @intCast(account.issuer.len), .big);
        @memcpy(output[i .. i + 4], &buf);
        i += 4;
        @memcpy(output[i .. i + account.issuer.len], account.issuer);
        i += account.issuer.len;

        std.mem.writeInt(u32, &buf, @intCast(account.name.len), .big);
        @memcpy(output[i .. i + 4], &buf);
        i += 4;
        @memcpy(output[i .. i + account.name.len], account.name);
        i += account.name.len;

        std.mem.writeInt(u32, &buf, @intCast(account.secret.len), .big);
        @memcpy(output[i .. i + 4], &buf);
        i += 4;
        @memcpy(output[i .. i + account.secret.len], account.secret);
        i += account.secret.len;
    }

    return output;
}

pub fn decode(al: std.mem.Allocator, bytes: []const u8) !Database {
    var i: usize = 0;
    if (bytes.len < 10) return error.InvalidFormat;
    if (!std.mem.eql(u8, bytes[0..4], "ZOTP")) return error.InvalidFormat;
    i += 4;

    const version = std.mem.readInt(u16, bytes[i..][0..2], .big);
    if (version != 1) return error.UnsupportedVersion;
    i += 2;

    var account_count = std.mem.readInt(u32, bytes[i..][0..4], .big);
    if (account_count > 4 * 1024) return error.InvalidFormat;
    i += 4;

    var accounts: std.ArrayList(Account) = try .initCapacity(al, account_count);
    errdefer {
        for (accounts.items) |account| {
            account.deinit(al);
        }
        accounts.deinit(al);
    }

    while (account_count > 0) : (account_count -= 1) {
        if (i >= bytes.len) return error.InvalidFormat;
        const algo = bytes[i];
        i += 1;
        if (i >= bytes.len) return error.InvalidFormat;
        const digits = bytes[i];
        if (digits != 6 and digits != 8) return error.InvalidFormat;
        i += 1;
        if (i + 4 >= bytes.len) return error.InvalidFormat;
        const period = std.mem.readInt(u32, bytes[i..][0..4], .big);
        i += 4;
        if (i + 4 >= bytes.len) return error.InvalidFormat;
        const issuer_len = std.mem.readInt(u32, bytes[i..][0..4], .big);
        i += 4;
        if (i + issuer_len >= bytes.len) return error.InvalidFormat;
        const issuer = try al.dupe(u8, bytes[i .. i + issuer_len]);
        errdefer al.free(issuer);
        i += issuer_len;
        if (i + 4 >= bytes.len) return error.InvalidFormat;
        const name_len = std.mem.readInt(u32, bytes[i..][0..4], .big);
        i += 4;
        if (i + name_len >= bytes.len) return error.InvalidFormat;
        const name = try al.dupe(u8, bytes[i .. i + name_len]);
        errdefer al.free(name);
        i += name_len;
        if (i + 4 >= bytes.len) return error.InvalidFormat;
        const secret_len = std.mem.readInt(u32, bytes[i..][0..4], .big);
        i += 4;
        if (i + secret_len > bytes.len) return error.InvalidFormat;
        const secret = try al.dupe(u8, bytes[i .. i + secret_len]);
        errdefer al.free(secret);
        i += secret_len;

        const account = Account{
            .issuer = issuer,
            .name = name,
            .secret = secret,
            .algorithm = switch (algo) {
                1 => .sha1,
                2 => .sha256,
                3 => .sha512,
                else => return error.InvalidFormat,
            },
            .digits = digits,
            .period = period,
        };
        accounts.appendAssumeCapacity(account);
    }

    var db = Database{ .accounts = try accounts.toOwnedSlice(al) };
    if (i != bytes.len) {
        db.deinit(al);
        return error.InvalidFormat;
    }

    return db;
}
