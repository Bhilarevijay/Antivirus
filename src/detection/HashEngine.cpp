/**
 * @file HashEngine.cpp
 * @brief Hash computation implementation
 * 
 * Uses modern C++ for portability. On Windows, can optionally
 * use Windows CNG for hardware acceleration.
 */

#include "antivirus/detection/HashEngine.hpp"
#include <fstream>
#include <iomanip>
#include <sstream>
#include <cstring>

namespace antivirus {

// Simple SHA-256 implementation (for portability)
// In production, use Windows CNG (BCrypt) or OpenSSL

namespace {

constexpr uint32_t K[] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

inline uint32_t rotr(uint32_t x, uint32_t n) {
    return (x >> n) | (x << (32 - n));
}

inline uint32_t ch(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (~x & z);
}

inline uint32_t maj(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

inline uint32_t sig0(uint32_t x) {
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
}

inline uint32_t sig1(uint32_t x) {
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
}

inline uint32_t gamma0(uint32_t x) {
    return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
}

inline uint32_t gamma1(uint32_t x) {
    return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
}

class SHA256Context {
public:
    SHA256Context() {
        Reset();
    }
    
    void Reset() {
        state[0] = 0x6a09e667;
        state[1] = 0xbb67ae85;
        state[2] = 0x3c6ef372;
        state[3] = 0xa54ff53a;
        state[4] = 0x510e527f;
        state[5] = 0x9b05688c;
        state[6] = 0x1f83d9ab;
        state[7] = 0x5be0cd19;
        count = 0;
        bufferLen = 0;
    }
    
    void Update(const uint8_t* data, size_t len) {
        count += len * 8;
        
        while (len > 0) {
            size_t toCopy = std::min(len, 64 - bufferLen);
            std::memcpy(buffer + bufferLen, data, toCopy);
            bufferLen += toCopy;
            data += toCopy;
            len -= toCopy;
            
            if (bufferLen == 64) {
                ProcessBlock(buffer);
                bufferLen = 0;
            }
        }
    }
    
    void Final(uint8_t* digest) {
        // Padding
        buffer[bufferLen++] = 0x80;
        
        if (bufferLen > 56) {
            std::memset(buffer + bufferLen, 0, 64 - bufferLen);
            ProcessBlock(buffer);
            bufferLen = 0;
        }
        
        std::memset(buffer + bufferLen, 0, 56 - bufferLen);
        
        // Length in bits (big-endian)
        for (int i = 0; i < 8; ++i) {
            buffer[56 + i] = static_cast<uint8_t>(count >> (56 - i * 8));
        }
        
        ProcessBlock(buffer);
        
        // Output hash (big-endian)
        for (int i = 0; i < 8; ++i) {
            digest[i * 4] = static_cast<uint8_t>(state[i] >> 24);
            digest[i * 4 + 1] = static_cast<uint8_t>(state[i] >> 16);
            digest[i * 4 + 2] = static_cast<uint8_t>(state[i] >> 8);
            digest[i * 4 + 3] = static_cast<uint8_t>(state[i]);
        }
    }
    
private:
    void ProcessBlock(const uint8_t* block) {
        uint32_t w[64];
        
        // Prepare message schedule
        for (int i = 0; i < 16; ++i) {
            w[i] = (static_cast<uint32_t>(block[i * 4]) << 24) |
                   (static_cast<uint32_t>(block[i * 4 + 1]) << 16) |
                   (static_cast<uint32_t>(block[i * 4 + 2]) << 8) |
                   (static_cast<uint32_t>(block[i * 4 + 3]));
        }
        
        for (int i = 16; i < 64; ++i) {
            w[i] = gamma1(w[i - 2]) + w[i - 7] + gamma0(w[i - 15]) + w[i - 16];
        }
        
        // Initialize working variables
        uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
        uint32_t e = state[4], f = state[5], g = state[6], h = state[7];
        
        // Main loop
        for (int i = 0; i < 64; ++i) {
            uint32_t t1 = h + sig1(e) + ch(e, f, g) + K[i] + w[i];
            uint32_t t2 = sig0(a) + maj(a, b, c);
            
            h = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }
        
        // Update state
        state[0] += a;
        state[1] += b;
        state[2] += c;
        state[3] += d;
        state[4] += e;
        state[5] += f;
        state[6] += g;
        state[7] += h;
    }
    
    uint32_t state[8];
    uint64_t count;
    uint8_t buffer[64];
    size_t bufferLen;
};

}  // namespace

class HashEngine::Impl {
public:
    SHA256Context sha256Ctx;
};

HashEngine::HashEngine()
    : m_impl(std::make_unique<Impl>())
{
}

HashEngine::~HashEngine() = default;

MD5Hash HashEngine::ComputeMD5(std::span<const uint8_t> data) const {
    // TODO: Implement MD5 or use platform API
    MD5Hash hash{};
    // Placeholder - in production use BCrypt or OpenSSL
    if (!data.empty()) {
        std::memcpy(hash.data(), data.data(), std::min(data.size(), hash.size()));
    }
    return hash;
}

SHA1Hash HashEngine::ComputeSHA1(std::span<const uint8_t> data) const {
    // TODO: Implement SHA-1 or use platform API
    SHA1Hash hash{};
    // Placeholder - in production use BCrypt or OpenSSL
    if (!data.empty()) {
        std::memcpy(hash.data(), data.data(), std::min(data.size(), hash.size()));
    }
    return hash;
}

SHA256Hash HashEngine::ComputeSHA256(std::span<const uint8_t> data) const {
    SHA256Hash hash{};
    
    SHA256Context ctx;
    ctx.Update(data.data(), data.size());
    ctx.Final(hash.data());
    
    return hash;
}

std::vector<uint8_t> HashEngine::ComputeFileHash(
    const FilePath& path,
    HashType type
) const {
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        return {};
    }
    
    SHA256Context ctx;
    std::vector<uint8_t> buffer(64 * 1024);  // 64KB chunks
    
    while (file) {
        file.read(reinterpret_cast<char*>(buffer.data()), 
            static_cast<std::streamsize>(buffer.size()));
        auto bytesRead = static_cast<size_t>(file.gcount());
        
        if (bytesRead > 0) {
            ctx.Update(buffer.data(), bytesRead);
        }
    }
    
    std::vector<uint8_t> hash;
    
    switch (type) {
        case HashType::SHA256: {
            hash.resize(32);
            ctx.Final(hash.data());
            break;
        }
        case HashType::SHA1:
            hash.resize(20);
            // TODO: Proper SHA-1
            break;
        case HashType::MD5:
            hash.resize(16);
            // TODO: Proper MD5
            break;
    }
    
    return hash;
}

void HashEngine::ComputeAllHashes(
    std::span<const uint8_t> data,
    MD5Hash& md5,
    SHA1Hash& sha1,
    SHA256Hash& sha256
) const {
    md5 = ComputeMD5(data);
    sha1 = ComputeSHA1(data);
    sha256 = ComputeSHA256(data);
}

std::string HashEngine::HashToHex(std::span<const uint8_t> hash) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    
    for (uint8_t byte : hash) {
        oss << std::setw(2) << static_cast<int>(byte);
    }
    
    return oss.str();
}

std::vector<uint8_t> HashEngine::HexToHash(const std::string& hex) {
    std::vector<uint8_t> result;
    result.reserve(hex.size() / 2);
    
    for (size_t i = 0; i + 1 < hex.size(); i += 2) {
        char highNibble = hex[i];
        char lowNibble = hex[i + 1];
        
        auto parseNibble = [](char c) -> uint8_t {
            if (c >= '0' && c <= '9') return static_cast<uint8_t>(c - '0');
            if (c >= 'a' && c <= 'f') return static_cast<uint8_t>(c - 'a' + 10);
            if (c >= 'A' && c <= 'F') return static_cast<uint8_t>(c - 'A' + 10);
            return 0;
        };
        
        uint8_t byte = (parseNibble(highNibble) << 4) | parseNibble(lowNibble);
        result.push_back(byte);
    }
    
    return result;
}

bool HashEngine::HashesEqual(
    std::span<const uint8_t> a,
    std::span<const uint8_t> b
) {
    if (a.size() != b.size()) {
        return false;
    }
    
    // Constant-time comparison to prevent timing attacks
    volatile uint8_t diff = 0;
    for (size_t i = 0; i < a.size(); ++i) {
        diff |= a[i] ^ b[i];
    }
    
    return diff == 0;
}

}  // namespace antivirus
