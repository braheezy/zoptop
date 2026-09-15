const std = @import("std");

pub const Algorithm = enum {
    sha1,
    sha256,
    sha512,

    pub fn fromString(data: []const u8) !Algorithm {
        return if (std.mem.eql(u8, data, "SHA1"))
            .sha1
        else if (std.mem.eql(u8, data, "SHA256"))
            .sha256
        else if (std.mem.eql(u8, data, "SHA512"))
            .sha512
        else
            error.UnsupportedAlgorithm;
    }
};
