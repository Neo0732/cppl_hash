#define forSHA1

#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <cstdint>

class SHA1 {
public:
    SHA1() { reset(); }

    void update(const std::string& s) {
        for (char c : s) {
            update((uint8_t)c);
        }
    }

    void update(uint8_t data) {
        buffer[bufferIndex++] = data;
        messageLength += 8;
        if (bufferIndex == 64) {
            processBlock();
            bufferIndex = 0;
        }
    }

    std::string final() {
        buffer[bufferIndex++] = 0x80;
        if (bufferIndex > 56) {
            while (bufferIndex < 64) buffer[bufferIndex++] = 0x00;
            processBlock();
            bufferIndex = 0;
        }
        while (bufferIndex < 56) buffer[bufferIndex++] = 0x00;

        uint64_t len = messageLength;
        for (int i = 7; i >= 0; --i) {
            buffer[bufferIndex++] = (uint8_t)((len >> (i * 8)) & 0xFF);
        }
        processBlock();

        std::ostringstream result;
        for (int i = 0; i < 5; ++i) {
            result << std::hex << std::setw(8) << std::setfill('0') << digest[i];
        }
        reset();
        return result.str();
    }

private:
    uint32_t digest[5];
    uint8_t buffer[64];
    size_t bufferIndex;
    uint64_t messageLength;

    void reset() {
        digest[0] = 0x67452301;
        digest[1] = 0xEFCDAB89;
        digest[2] = 0x98BADCFE;
        digest[3] = 0x10325476;
        digest[4] = 0xC3D2E1F0;
        bufferIndex = 0;
        messageLength = 0;
    }

    void processBlock() {
        uint32_t w[80];
        for (int i = 0; i < 16; ++i) {
            w[i] = (buffer[i * 4] << 24) | (buffer[i * 4 + 1] << 16) |
                   (buffer[i * 4 + 2] << 8) | buffer[i * 4 + 3];
        }
        for (int i = 16; i < 80; ++i) {
            w[i] = rotl(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
        }

        uint32_t a = digest[0], b = digest[1], c = digest[2], d = digest[3], e = digest[4];

        for (int i = 0; i < 80; ++i) {
            uint32_t f, k;
            if (i < 20) {
                f = (b & c) | ((~b) & d);
                k = 0x5A827999;
            } else if (i < 40) {
                f = b ^ c ^ d;
                k = 0x6ED9EBA1;
            } else if (i < 60) {
                f = (b & c) | (b & d) | (c & d);
                k = 0x8F1BBCDC;
            } else {
                f = b ^ c ^ d;
                k = 0xCA62C1D6;
            }
            uint32_t temp = rotl(a, 5) + f + e + k + w[i];
            e = d;
            d = c;
            c = rotl(b, 30);
            b = a;
            a = temp;
        }

        digest[0] += a;
        digest[1] += b;
        digest[2] += c;
        digest[3] += d;
        digest[4] += e;
    }

    uint32_t rotl(uint32_t value, int bits) {
        return (value << bits) | (value >> (32 - bits));
    }
};

int main() {
    SHA1 sha1;
    std::string input = "hello world";
    sha1.update(input);
    std::string hash = sha1.final();
    std::cout << "SHA1(\"" << input << "\") = " << hash << std::endl;
    return 0;
}
