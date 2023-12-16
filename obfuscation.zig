/// Encryption function for the Caeser Cipher at compile time
pub inline fn caeser_encrypt(comptime plaintext: []const u8, comptime shift: u8) *const [plaintext.len]u8 {
    comptime {
        var buf: [plaintext.len]u8 = undefined;
        for (plaintext, 0..) |c, i| {
            var tmp: u8 = c + shift;
            buf[i] = tmp;
        }
        return &buf;
    }
}

/// Decryption function (during runtime)
pub fn caesar_decrypt(cipher: []const u8, shift: u8, buf: [*]u8) void {
    for (cipher, 0..) |c, i| {
        var tmp: u8 = c - shift;
        buf[i] = tmp;
    }
}
