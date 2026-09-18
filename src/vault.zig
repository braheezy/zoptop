const std = @import("std");

pub fn seal(
    al: std.mem.Allocator,
    io: std.Io,
    password: []const u8,
    plaintext: []const u8,
    options: SealOptions,
) ![]u8 {
    if (plaintext.len > 4 * 1024 * 1024) return error.InvalidFormat;
    if (options.params.t < 1 or options.params.t > 10) return error.InvalidKdfParameters;
    if (options.params.p < 1 or options.params.p > 4) return error.InvalidKdfParameters;
    if (options.params.m < 8 * options.params.p or options.params.m > 262144) return error.InvalidKdfParameters;

    var header: [64]u8 = undefined;
    var i: usize = 0;

    @memcpy(header[i .. i + 4], "ZVLT");
    i += 4;

    const version: u8 = 1;
    std.mem.writeInt(u8, &header[i], version, .big);
    i += 1;

    const crypto: u8 = 1;
    std.mem.writeInt(u8, &header[i], crypto, .big);
    i += 1;

    const argon2_version: u8 = 0x13;
    std.mem.writeInt(u8, &header[i], argon2_version, .big);
    i += 1;

    const reserved: u8 = 0;
    std.mem.writeInt(u8, &header[i], reserved, .big);
    i += 1;

    std.mem.writeInt(u32, header[i..][0..4], options.params.t, .big);
    i += 4;

    std.mem.writeInt(u32, header[i..][0..4], options.params.m, .big);
    i += 4;

    std.mem.writeInt(u32, header[i..][0..4], options.params.p, .big);
    i += 4;

    // salt
    try io.randomSecure(header[i..][0..16]);
    i += 16;
    // nonce
    try io.randomSecure(header[i..][0..24]);
    i += 24;

    std.mem.writeInt(u32, header[i..][0..4], @intCast(plaintext.len), .big);
    i += 4;

    var key: [32]u8 = undefined;
    defer std.crypto.secureZero(u8, &key);
    try std.crypto.pwhash.argon2.kdf(
        al,
        &key,
        password,
        header[20..36],
        .{
            .t = options.params.t,
            .m = options.params.m,
            .p = options.params.p,
        },
        .argon2id,
        io,
    );

    const output = try al.alloc(u8, 64 + plaintext.len + 16);
    @memcpy(output[0..64], &header);

    const tag_start = 64 + plaintext.len;
    std.crypto.aead.chacha_poly.XChaCha20Poly1305.encrypt(
        output[64..tag_start], // encrypted bytes output
        output[tag_start..][0..16], // authentication tag
        plaintext, // bytes to encrypt
        &header, // protected against changes, but not encrypted
        header[36..60].*, // 24-byte nonce
        key, // 32-byte derived key
    );

    return output;
}

pub fn open(
    al: std.mem.Allocator,
    io: std.Io,
    password: []const u8,
    encrypted: []const u8,
) ![]u8 {
    if (encrypted.len < 80) return error.InvalidVault;
    if (!std.mem.eql(u8, encrypted[0..4], "ZVLT")) return error.InvalidFormat;
    if (encrypted.len < 80 or encrypted.len > 4 * 1024 * 1024 + 80)
        return error.InvalidVault;

    const tag_start = encrypted.len - 16;
    const ciphertext = encrypted[64..tag_start];
    const header = encrypted[0..64];
    var i: usize = 4;

    const version = header[i];
    if (version != 1) return error.UnsupportedVersion;
    i += 1;

    const crypto = header[i];
    if (crypto != 1) return error.UnsupportedVersion;
    i += 1;

    const argon2_version = header[i];
    if (argon2_version != 0x13) return error.UnsupportedVersion;
    i += 1;

    const reserved_version = header[i];
    if (reserved_version != 0) return error.UnsupportedVersion;
    i += 1;

    const t = std.mem.readInt(u32, header[i..][0..4], .big);
    i += 4;
    if (t > 10 or t < 1) return error.InvalidFormat;

    const m = std.mem.readInt(u32, header[i..][0..4], .big);
    i += 4;

    const p = std.mem.readInt(u32, header[i..][0..4], .big);
    i += 4;
    if (p < 1 or p > 4) return error.InvalidKdfParameters;
    if (m < 8 * p or m > 262144) return error.InvalidKdfParameters;

    // salt
    _ = header[i .. i + 16];
    i += 16;
    // nonce
    _ = header[i .. i + 24];
    i += 24;

    const plaintext_len = std.mem.readInt(u32, header[i..][0..4], .big);
    i += 4;

    const plaintext = try al.alloc(u8, ciphertext.len);
    errdefer {
        std.crypto.secureZero(u8, plaintext);
        al.free(plaintext);
    }

    var key: [32]u8 = undefined;
    defer std.crypto.secureZero(u8, &key);
    try std.crypto.pwhash.argon2.kdf(
        al,
        &key,
        password,
        header[20..36],
        .{
            .t = t,
            .m = m,
            .p = @intCast(p),
        },
        .argon2id,
        io,
    );
    if (plaintext.len != plaintext_len) return error.InvalidVault;

    try std.crypto.aead.chacha_poly.XChaCha20Poly1305.decrypt(
        plaintext,
        ciphertext,
        encrypted[tag_start..][0..16].*,
        header,
        encrypted[36..60].*,
        key,
    );

    return plaintext;
}

pub const SealOptions = struct {
    params: struct {
        t: u32 = 3,
        m: u32 = 65536,
        p: u24 = 4,
    },
};

// These expected bytes come from argon2-cffi 25.1.0 and PyNaCl 1.6.2 (libsodium),
// not Zig's crypto implementation. To reproduce them in Python:
//
// from argon2.low_level import hash_secret_raw, Type
// from nacl.bindings import crypto_aead_xchacha20poly1305_ietf_encrypt
// import struct
// password = b"fixture password"
// plaintext = b"vault fixture\x00\xff"
// salt, nonce = bytes(range(16)), bytes(range(16, 40))
// key = hash_secret_raw(password, salt, time_cost=2, memory_cost=32,
//     parallelism=2, hash_len=32, type=Type.ID, version=19)
// header = (b"ZVLT" + bytes([1, 1, 19, 0]) + struct.pack(">III", 2, 32, 2)
//     + salt + nonce + struct.pack(">I", len(plaintext)))
// result = header + crypto_aead_xchacha20poly1305_ietf_encrypt(
//     plaintext, header, nonce, key)
// print(result.hex())
const TestFixture = struct {
    const password = "fixture password";
    const plaintext = "vault fixture\x00\xff";
    // Cheap parameters for tests only. Two lanes also exercise the stored p field.
    const options: SealOptions = .{ .params = .{ .t = 2, .m = 32, .p = 2 } };
    const hex = "5a564c5401011300000000020000002000000002" ++
        "000102030405060708090a0b0c0d0e0f" ++
        "101112131415161718191a1b1c1d1e1f2021222324252627" ++
        "0000000f" ++
        "9907b05334bd660acc3ad7c9bcf92a" ++
        "3fc41095834634add1a28ccf50bd2136";

    fn bytes() ![hex.len / 2]u8 {
        var result: [hex.len / 2]u8 = undefined;
        _ = try std.fmt.hexToBytes(&result, hex);
        return result;
    }
};

test "vault: seal matches independent Argon2id and libsodium bytes" {
    const testing = std.testing;
    // This replacement exists only inside this test. seal still calls
    // io.randomSecure; normal callers keep their real random source.
    const FixedRandom = struct {
        fn fill(_: ?*anyopaque, buffer: []u8) std.Io.RandomSecureError!void {
            const start: usize = switch (buffer.len) {
                16 => 0, // Salt: 00 through 0f.
                24 => 16, // Nonce: 10 through 27.
                else => return error.EntropyUnavailable,
            };
            for (buffer, 0..) |*byte, index| byte.* = @intCast(start + index);
        }
    };
    var vtable = testing.io.vtable.*;
    vtable.randomSecure = FixedRandom.fill;
    const fixed_io: std.Io = .{ .userdata = testing.io.userdata, .vtable = &vtable };

    const actual = try seal(testing.allocator, fixed_io, TestFixture.password, TestFixture.plaintext, TestFixture.options);
    defer testing.allocator.free(actual);
    const expected = try TestFixture.bytes();
    // Compare the entire vault: header, ciphertext, and authentication tag.
    try testing.expectEqualSlices(u8, &expected, actual);
}

test "vault: open reads independent Argon2id and libsodium bytes" {
    const testing = std.testing;
    const encrypted = try TestFixture.bytes();
    // Do not call seal here: open must work with bytes made outside this library.
    const plaintext = try open(testing.allocator, testing.io, TestFixture.password, &encrypted);
    defer {
        std.crypto.secureZero(u8, plaintext);
        testing.allocator.free(plaintext);
    }
    try testing.expectEqualSlices(u8, TestFixture.plaintext, plaintext);
}
