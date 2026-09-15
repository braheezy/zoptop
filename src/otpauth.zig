const std = @import("std");
const base32 = @import("base32.zig");
const Algorithm = @import("algorithm.zig").Algorithm;
const testing = std.testing;
const Allocator = std.mem.Allocator;
const Account = @import("Account.zig");

fn decodeComponent(allocator: Allocator, input: []const u8) ![]u8 {
    var i: usize = 0;
    var output: std.ArrayList(u8) = try .initCapacity(allocator, input.len / 2);
    defer output.deinit(allocator);
    while (i < input.len) {
        const byte = input[i];
        if (byte != '%') {
            try output.append(allocator, byte);
            i += 1;
        } else {
            if (input.len - i < 3) return error.InvalidUri;

            const hex_chars = input[i + 1 ..][0..2];
            if (!std.ascii.isHex(hex_chars[0])) return error.InvalidUri;
            if (!std.ascii.isHex(hex_chars[1])) return error.InvalidUri;

            const decoded = std.fmt.parseInt(u8, hex_chars, 16) catch return error.InvalidUri;
            try output.append(allocator, decoded);

            i += 3;
        }
    }
    return output.toOwnedSlice(allocator);
}

pub fn parse(allocator: Allocator, input: []const u8) !Account {
    if (input.len < 15) return error.InvalidUri;
    if (!std.mem.eql(u8, input[0..15], "otpauth://totp/")) return error.InvalidUri;
    const settings_index = std.mem.find(u8, input, "?") orelse return error.InvalidUri;
    const label = input[15..settings_index];
    const settings = input[settings_index + 1 ..];

    var issuer: ?[]const u8 = null;
    errdefer if (issuer) |bytes| allocator.free(bytes);
    var secret: ?[]const u8 = null;
    defer if (secret) |bytes| allocator.free(bytes);
    var algorithm: ?Algorithm = null;
    var digits: ?u8 = null;
    var period: ?u32 = null;

    var it = std.mem.splitScalar(u8, settings, '&');
    while (it.next()) |setting| {
        const kv_index = std.mem.find(u8, setting, "=") orelse return error.InvalidUri;
        const setting_key = try decodeComponent(allocator, setting[0..kv_index]);

        // std.debug.print("setting_key: {s}\n", .{setting_key});
        defer allocator.free(setting_key);
        const setting_value = try decodeComponent(allocator, setting[kv_index + 1 ..]);
        defer allocator.free(setting_value);
        // std.debug.print("setting_value: {s}\n", .{setting_value});
        if (setting_key.len == 0) return error.InvalidUri;
        if (setting_value.len == 0) return error.InvalidUri;

        if (std.mem.eql(u8, setting_key, "secret")) {
            if (secret) |_| {
                return error.InvalidUri;
            } else {
                secret = try allocator.dupe(u8, setting_value);
            }
        } else if (std.mem.eql(u8, setting_key, "issuer")) {
            if (issuer) |_| {
                return error.InvalidUri;
            } else {
                issuer = try allocator.dupe(u8, setting_value);
            }
        } else if (std.mem.eql(u8, setting_key, "digits")) {
            if (digits) |_| {
                return error.InvalidUri;
            } else {
                if (!std.mem.eql(u8, setting_value, "8") and !std.mem.eql(u8, setting_value, "6")) return error.InvalidUri;
                digits = try std.fmt.parseInt(u8, setting_value, 10);
            }
        } else if (std.mem.eql(u8, setting_key, "period")) {
            if (period) |_| {
                return error.InvalidUri;
            } else {
                if (!std.ascii.isDigit(setting_value[0])) return error.InvalidUri;
                if (std.mem.count(u8, setting_value, "_") > 0) return error.InvalidUri;
                period = std.fmt.parseInt(u32, setting_value, 10) catch return error.InvalidUri;
                if (period == 0) return error.InvalidUri;
            }
        } else if (std.mem.eql(u8, setting_key, "algorithm")) {
            if (algorithm) |_| {
                return error.InvalidUri;
            } else {
                algorithm = Algorithm.fromString(setting_value) catch return error.InvalidUri;
            }
        }
    }

    const full_label = try decodeComponent(allocator, label);
    defer allocator.free(full_label);
    var decoded_label: []const u8 = full_label;
    if (std.mem.find(u8, decoded_label, ":")) |idx| {
        if (idx == 0) return error.InvalidUri;
        const issuer_from_label = try allocator.dupe(u8, decoded_label[0..idx]);
        if (issuer) |iss| {
            if (!std.mem.eql(u8, issuer_from_label, iss)) {
                allocator.free(issuer_from_label);
                return error.InvalidUri;
            }
            allocator.free(iss);
        }
        issuer = issuer_from_label;
        decoded_label = std.mem.trimStart(u8, decoded_label[idx + 1 ..], " ");
        if (std.mem.find(u8, decoded_label, ":")) |_| return error.InvalidUri;
    }

    if (decoded_label.len == 0) return error.InvalidUri;

    if (issuer == null) {
        issuer = try allocator.alloc(u8, 0);
    }
    if (std.mem.count(u8, issuer.?, ":") > 0) return error.InvalidUri;

    if (!std.unicode.utf8ValidateSlice(decoded_label)) return error.InvalidUri;
    if (!std.unicode.utf8ValidateSlice(issuer.?)) return error.InvalidUri;
    for (decoded_label) |byte| {
        if (byte < 0x20 or byte == 0x7f) return error.InvalidUri;
    }
    for (issuer.?) |byte| {
        if (byte < 0x20 or byte == 0x7f) return error.InvalidUri;
    }

    const decoded_secret = if (secret) |sec|
        base32.decode(allocator, sec) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.InvalidUri,
        }
    else
        return error.InvalidUri;
    errdefer allocator.free(decoded_secret);

    // std.debug.print("label: {s}\n", .{label});
    // std.debug.print("secret: {s}\n", .{secret.?});
    return .{
        .name = try allocator.dupe(u8, decoded_label),
        .issuer = issuer.?,
        .digits = digits orelse 6,
        .period = period orelse 30,
        .algorithm = algorithm orelse .sha1,
        .secret = decoded_secret,
    };
}

fn expectComponent(input: []const u8, expected: []const u8) !void {
    const actual = try decodeComponent(testing.allocator, input);
    defer testing.allocator.free(actual);
    try testing.expectEqualSlices(u8, expected, actual);
}

test "URI percent decoding" {
    try expectComponent("Acme%20Co", "Acme Co");
    try expectComponent("Acme%3aalice", "Acme:alice");
    try expectComponent("alice+work%40example.com", "alice+work@example.com");
    try expectComponent("%2520", "%20");
    try expectComponent("caf%C3%A9", "café");
    try expectComponent("", "");
}

test "URI rejects broken percent escapes" {
    for ([_][]const u8{ "%", "%2", "%GG", "ok%0Z", "%+1", "%_1" }) |input| {
        errdefer std.debug.print("\nInvalid percent escape: {s}\n", .{input});
        if (decodeComponent(testing.allocator, input)) |bytes| {
            testing.allocator.free(bytes);
            return error.TestUnexpectedSuccess;
        } else |err| {
            try testing.expectEqual(error.InvalidUri, err);
        }
    }
}

fn expectAccount(input: []const u8, issuer: []const u8, name: []const u8) !void {
    errdefer std.debug.print("\nURI test input: {s}\n", .{input});
    const account = try parse(testing.allocator, input);
    defer account.deinit(testing.allocator);
    try testing.expectEqualSlices(u8, issuer, account.issuer);
    try testing.expectEqualSlices(u8, name, account.name);
    try testing.expectEqualSlices(u8, "f", account.secret);
    try testing.expectEqual(@as(u8, 6), account.digits);
    try testing.expectEqual(@as(u32, 30), account.period);
}

test "URI simplest account" {
    try expectAccount("otpauth://totp/alice?secret=MY", "", "alice");
}

test "URI issuer and account names" {
    try expectAccount("otpauth://totp/Acme:alice?secret=MY", "Acme", "alice");
    try expectAccount("otpauth://totp/alice?issuer=Acme&secret=MY", "Acme", "alice");
    try expectAccount(
        "otpauth://totp/Acme%20Co%3A%20alice+work%40example.com?secret=MY&issuer=Acme%20Co",
        "Acme Co",
        "alice+work@example.com",
    );
    try expectAccount("otpauth://totp/caf%C3%A9?secret=MY", "", "café");
    try expectAccount(
        "otpauth://totp/alice?secret=MY&issuer=Research%26Tools",
        "Research&Tools",
        "alice",
    );
}

test "URI decodes keys and values once" {
    try expectAccount(
        "otpauth://totp/alice%2520?%73ecret=M%59%3D%3D%3D%3D%3D%3D&algorithm=SHA1&extra=a%26b",
        "",
        "alice%20",
    );
}

test "URI settings reach the TOTP generator" {
    const account = try parse(
        testing.allocator,
        "otpauth://totp/Example:alice?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=8&period=60",
    );
    defer account.deinit(testing.allocator);
    const Totp = @import("totp.zig").Totp;
    const generator = Totp{
        .secret = account.secret,
        .digits = account.digits,
        .period = account.period,
    };
    try testing.expectEqual(@as(u8, 8), account.digits);
    try testing.expectEqual(@as(u32, 60), account.period);
    // At 119 seconds with a 60-second period, the HOTP counter is 1.
    try testing.expectEqual(@as(u32, 94287082), try generator.generate(119));
}

fn expectInvalid(input: []const u8) !void {
    errdefer std.debug.print("\nInvalid URI test input: {s}\n", .{input});
    if (parse(testing.allocator, input)) |account| {
        account.deinit(testing.allocator);
        return error.TestUnexpectedSuccess;
    } else |err| {
        try testing.expectEqual(error.InvalidUri, err);
    }
}

test "URI rejects bad structure and names" {
    for ([_][]const u8{
        "https://totp/alice?secret=MY",
        "otpauth://hotp/alice?secret=MY",
        "otpauth://totp/alice",
        "otpauth://totp/?secret=MY",
        "otpauth://totp/:alice?secret=MY",
        "otpauth://totp/Acme:?secret=MY",
        "otpauth://totp/Acme:alice:work?secret=MY",
        "otpauth://totp/alice%?secret=MY",
        "otpauth://totp/alice%FF?secret=MY",
        "otpauth://totp/alice%0A?secret=MY",
        "otpauth://totp/alice?secret=MY#fragment",
        "otpauth://totp/alice?secret=MY&",
        "otpauth://totp/alice?secret=MY&extra",
        "otpauth://totp/alice?secret=MY&=x",
        "otpauth://totp/alice?secret=MY&extra=%GG",
    }) |input| try expectInvalid(input);
}

test "URI rejects bad settings" {
    const prefix = "otpauth://totp/alice?";
    inline for (.{
        "issuer=Acme",                 "secret=",                                 "secret=ABC123",                 "secret=MZ",
        "secret=MY&secret=MY",         "secret=MY&%73ecret=MY",                   "secret=MY&algorithm=MD5",       "secret=MY&algorithm=MD5",
        "secret=MY&algorithm=",        "secret=MY&algorithm=SHA1&algorithm=SHA1", "secret=MY&digits=7",            "secret=MY&digits=",
        "secret=MY&digits=6&digits=6", "secret=MY&period=0",                      "secret=MY&period=-1",           "secret=MY&period=%2B30",
        "secret=MY&period=",           "secret=MY&period=4294967296",             "secret=MY&period=30&period=30", "secret=MY&period=3_0",
        "secret=MY&issuer=",           "secret=MY&issuer=Acme&issuer=Acme",       "secret=MY&issuer=A%3AB",        "secret=MY&issuer=%1B",
    }) |query| try expectInvalid(prefix ++ query);
    try expectInvalid("otpauth://totp/Acme:alice?secret=MY&issuer=Other");
}

test "URI rejects digits with leading zeros or signs" {
    inline for (.{ "06", "08", "%2B6", "%2B8", "0_6" }) |digits| {
        try expectInvalid("otpauth://totp/alice?secret=MY&digits=" ++ digits);
    }
}

test "URI reports invalid numeric digits as InvalidUri" {
    try expectInvalid("otpauth://totp/alice?secret=MY&digits=six");
}

test "URI reports overflowing digits as InvalidUri" {
    try expectInvalid("otpauth://totp/alice?secret=MY&digits=256");
}

test "URI accepts exactly six or eight digits after percent decoding" {
    inline for (.{ "6", "8", "%36", "%38" }, .{ 6, 8, 6, 8 }) |digits, expected| {
        const account = try parse(testing.allocator, "otpauth://totp/alice?secret=MY&digits=" ++ digits);
        defer account.deinit(testing.allocator);
        try testing.expectEqual(@as(u8, expected), account.digits);
    }
}

test "URI account does not borrow the input string" {
    const input = try testing.allocator.dupe(u8, "otpauth://totp/Acme:alice?secret=MY");
    defer testing.allocator.free(input);
    const account = try parse(testing.allocator, input);
    defer account.deinit(testing.allocator);
    @memset(input, 'x');
    try testing.expectEqualSlices(u8, "Acme", account.issuer);
    try testing.expectEqualSlices(u8, "alice", account.name);
    try testing.expectEqualSlices(u8, "f", account.secret);
}

// anyerror keeps this helper usable while parse still returns NotImplemented.
fn allocationCase(allocator: Allocator) anyerror!void {
    const account = try parse(
        allocator,
        "otpauth://totp/Acme%20Co:alice?secret=MY&issuer=Acme%20Co",
    );
    defer account.deinit(allocator);
    try testing.expectEqualSlices(u8, "Acme Co", account.issuer);
}

test "URI handles allocation failure" {
    try testing.checkAllAllocationFailures(testing.allocator, allocationCase, .{});
}
