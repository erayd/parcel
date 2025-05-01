"use strict";

export class Helpers {
    /**
     * Convert a base32 string to an ArrayBuffer.
     * @since 1.0.0
     * @param {string} s - The base32 string to convert.
     * @returns {ArrayBuffer} The converted ArrayBuffer.
     */
    static base32ToArrayBuffer(s) {
        const dict = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        s = s.toUpperCase();
        const bytes = new Uint8Array(Math.floor((s.length * 5) / 8));
        let buf = 0,
            j = 0,
            val = 0,
            bits = 0;
        for (let i of s) {
            val = dict.indexOf(i);
            buf = (buf << 5) | (val & 0x1f);
            bits += 5;
            if (bits >= 8) {
                bits -= 8;
                bytes[j++] = (buf >> bits) & 0xff;
            }
        }
        return bytes.buffer;
    }

    /**
     * Generate a TOTP token.
     * @since 1.0.0
     * @param {string} secret - The base32 secret key.
     * @param {number} [step=30] - The time step in seconds.
     * @param {number} [digits=6] - The number of digits in the token.
     * @returns {Promise<string>} The generated TOTP token.
     */
    static async generateTOTP(secret, step = 30, digits = 6) {
        const counter = new Uint8Array(8);
        let now = Math.floor(Date.now() / (step * 1000));
        for (let i = 7; i >= 0; i--) {
            counter[i] = now & 0xff;
            now >>= 8;
        }

        const key = await crypto.subtle.importKey("raw", Helpers.base32ToArrayBuffer(secret), { name: "HMAC", hash: "SHA-1" }, false, [
            "sign",
        ]);
        const HS = new Uint8Array(await crypto.subtle.sign("HMAC", key, counter.buffer));
        const offset = HS[19] & 0x0f;
        const num = ((HS[offset] & 0x7f) << 24) | (HS[offset + 1] << 16) | (HS[offset + 2] << 8) | HS[offset + 3];

        return (num % Math.pow(10, digits)).toString().padStart(digits, "0");
    }

    /**
     * Generate a SHA-256 hash of a string.
     * @since 1.0.0
     * @param {string} str - The string to hash.
     * @returns {Promise<string>} The SHA-256 hash of the string.
     */
    static async sha256(s) {
        const data = new TextEncoder().encode(s);
        const hashBuffer = await crypto.subtle.digest("SHA-256", data);
        const hashArray = Array.from(new Uint8Array(hashBuffer));

        return hashArray.map((i) => i.toString(16).padStart(2, "0")).join("");
    }
}
