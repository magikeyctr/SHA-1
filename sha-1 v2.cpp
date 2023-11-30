#include <iostream>
#include <iomanip>
#include <sstream>
#include <cstdint>
#include <vector>

class SHA1 {
public:
    std::string calculate(const std::string& input) {
        uint32_t h0 = 0x67452301;
        uint32_t h1 = 0xEFCDAB89;
        uint32_t h2 = 0x98BADCFE;
        uint32_t h3 = 0x10325476;
        uint32_t h4 = 0xC3D2E1F0;

        std::vector<uint8_t> data = preprocess(input);

        for (std::size_t i = 0; i < data.size(); i += 64) {
            processBlock(&data[i], h0, h1, h2, h3, h4);
        }

        std::stringstream ss;
        ss << std::hex << std::setfill('0')
           << std::setw(8) << h0
           << std::setw(8) << h1
           << std::setw(8) << h2
           << std::setw(8) << h3
           << std::setw(8) << h4;

        return ss.str();
    }

private:
    std::vector<uint8_t> preprocess(const std::string& input) {
        std::vector<uint8_t> data(input.begin(), input.end());

        data.push_back(0x80);

        while ((data.size() % 64) != 56) {
            data.push_back(0x00);
        }

        uint64_t bitLength = input.length() * 8;
        for (int i = 56; i >= 0; i -= 8) {
            data.push_back((bitLength >> i) & 0xFF);
        }

        return data;
    }

    void processBlock(const uint8_t* block, uint32_t& h0, uint32_t& h1, uint32_t& h2, uint32_t& h3, uint32_t& h4) {
        std::vector<uint32_t> w(80, 0);

        for (int i = 0; i < 16; ++i) {
            w[i] = (block[i * 4] << 24) | (block[i * 4 + 1] << 16) | (block[i * 4 + 2] << 8) | block[i * 4 + 3];
        }

        for (int i = 16; i < 80; ++i) {
            w[i] = leftRotate((w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]), 1);
        }

        uint32_t a = h0;
        uint32_t b = h1;
        uint32_t c = h2;
        uint32_t d = h3;
        uint32_t e = h4;

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

            uint32_t temp = leftRotate(a, 5) + f + e + k + w[i];
            e = d;
            d = c;
            c = leftRotate(b, 30);
            b = a;
            a = temp;
        }

        h0 += a;
        h1 += b;
        h2 += c;
        h3 += d;
        h4 += e;
    }

    uint32_t leftRotate(uint32_t value, int shift) {
        return (value << shift) | (value >> (32 - shift));
    }
};

int main() {
    SHA1 sha1;
    std::string input = "abcd";
    std::string hash = sha1.calculate(input);
    std::cout << "SHA-1 Hash: " << hash << std::endl;

    return 0;
}
