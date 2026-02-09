/**
 * @file BloomFilter.cpp
 * @brief Bloom filter implementation
 */

#include "antivirus/detection/BloomFilter.hpp"
#include <cmath>
#include <cstring>
#include <algorithm>

namespace antivirus {

BloomFilter::BloomFilter(size_t expectedItems, double falsePositiveRate) 
    : m_bits(CalculateBitCount(expectedItems, falsePositiveRate))
    , m_hashCount(CalculateHashCount(m_bits.size(), expectedItems))
{
}

BloomFilter::BloomFilter(size_t bitCount, size_t hashCount)
    : m_bits(bitCount)
    , m_hashCount(hashCount)
{
}

void BloomFilter::Insert(std::span<const uint8_t> data) {
    auto indices = GetHashIndices(data);
    for (size_t idx : indices) {
        m_bits[idx] = true;
    }
    ++m_itemCount;
}

void BloomFilter::InsertHash(const std::array<uint8_t, 32>& hash) {
    Insert(std::span<const uint8_t>(hash.data(), hash.size()));
}

bool BloomFilter::MayContain(std::span<const uint8_t> data) const {
    auto indices = GetHashIndices(data);
    for (size_t idx : indices) {
        if (!m_bits[idx]) {
            return false;  // Definitely not present
        }
    }
    return true;  // Possibly present
}

bool BloomFilter::MayContainHash(const std::array<uint8_t, 32>& hash) const {
    return MayContain(std::span<const uint8_t>(hash.data(), hash.size()));
}

void BloomFilter::Clear() {
    std::fill(m_bits.begin(), m_bits.end(), false);
    m_itemCount = 0;
}

size_t BloomFilter::GetPopulationCount() const {
    size_t count = 0;
    for (bool bit : m_bits) {
        if (bit) ++count;
    }
    return count;
}

double BloomFilter::GetEstimatedFalsePositiveRate() const {
    double p = static_cast<double>(GetPopulationCount()) / m_bits.size();
    return std::pow(p, static_cast<double>(m_hashCount));
}

std::vector<size_t> BloomFilter::GetHashIndices(std::span<const uint8_t> data) const {
    std::vector<size_t> indices(m_hashCount);
    
    uint64_t h1 = Hash1(data);
    uint64_t h2 = Hash2(data);
    
    // Double hashing: h_i = h1 + i * h2
    for (size_t i = 0; i < m_hashCount; ++i) {
        indices[i] = (h1 + i * h2) % m_bits.size();
    }
    
    return indices;
}

size_t BloomFilter::CalculateBitCount(size_t n, double p) {
    // m = -n * ln(p) / (ln(2)^2)
    double ln2 = std::log(2.0);
    double m = -static_cast<double>(n) * std::log(p) / (ln2 * ln2);
    return static_cast<size_t>(std::ceil(m));
}

size_t BloomFilter::CalculateHashCount(size_t m, size_t n) {
    // k = (m/n) * ln(2)
    double k = (static_cast<double>(m) / n) * std::log(2.0);
    return static_cast<size_t>(std::round(k));
}

// MurmurHash3-inspired hash functions
uint64_t BloomFilter::Hash1(std::span<const uint8_t> data) {
    uint64_t h = 0x9e3779b97f4a7c15ULL;
    
    for (size_t i = 0; i + 8 <= data.size(); i += 8) {
        uint64_t k;
        std::memcpy(&k, data.data() + i, 8);
        
        k *= 0x87c37b91114253d5ULL;
        k = (k << 31) | (k >> 33);
        k *= 0x4cf5ad432745937fULL;
        
        h ^= k;
        h = (h << 27) | (h >> 37);
        h = h * 5 + 0x52dce729;
    }
    
    // Handle remaining bytes
    size_t remaining = data.size() % 8;
    if (remaining > 0) {
        uint64_t k = 0;
        std::memcpy(&k, data.data() + data.size() - remaining, remaining);
        h ^= k;
    }
    
    h ^= data.size();
    h ^= h >> 33;
    h *= 0xff51afd7ed558ccdULL;
    h ^= h >> 33;
    h *= 0xc4ceb9fe1a85ec53ULL;
    h ^= h >> 33;
    
    return h;
}

uint64_t BloomFilter::Hash2(std::span<const uint8_t> data) {
    uint64_t h = 0xc6a4a7935bd1e995ULL;
    
    for (size_t i = 0; i + 8 <= data.size(); i += 8) {
        uint64_t k;
        std::memcpy(&k, data.data() + i, 8);
        
        k *= 0xc6a4a7935bd1e995ULL;
        k ^= k >> 47;
        k *= 0xc6a4a7935bd1e995ULL;
        
        h ^= k;
        h *= 0xc6a4a7935bd1e995ULL;
    }
    
    size_t remaining = data.size() % 8;
    if (remaining > 0) {
        uint64_t k = 0;
        std::memcpy(&k, data.data() + data.size() - remaining, remaining);
        h ^= k;
        h *= 0xc6a4a7935bd1e995ULL;
    }
    
    h ^= h >> 47;
    h *= 0xc6a4a7935bd1e995ULL;
    h ^= h >> 47;
    
    return h;
}

}  // namespace antivirus
