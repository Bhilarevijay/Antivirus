/**
 * @file SIMDUtils.hpp
 * @brief SIMD intrinsics wrappers for high-performance byte operations
 * 
 * Provides AVX2/SSE4.2 optimized operations for byte comparison,
 * pattern matching, and data transformation.
 */

#pragma once

#include <cstdint>
#include <cstddef>
#include <array>
#include <span>

#if defined(_MSC_VER)
    #include <intrin.h>
#else
    #include <immintrin.h>
    #include <x86intrin.h>
#endif

namespace antivirus {
namespace simd {

/**
 * @brief Check if AVX2 is supported
 */
[[nodiscard]] inline bool HasAVX2() noexcept {
#if defined(_MSC_VER)
    int cpuInfo[4];
    __cpuid(cpuInfo, 7);
    return (cpuInfo[1] & (1 << 5)) != 0;
#else
    return __builtin_cpu_supports("avx2");
#endif
}

/**
 * @brief Check if SSE4.2 is supported
 */
[[nodiscard]] inline bool HasSSE42() noexcept {
#if defined(_MSC_VER)
    int cpuInfo[4];
    __cpuid(cpuInfo, 1);
    return (cpuInfo[2] & (1 << 20)) != 0;
#else
    return __builtin_cpu_supports("sse4.2");
#endif
}

/**
 * @brief Fast memory comparison using AVX2
 * @param a First buffer
 * @param b Second buffer
 * @param size Size in bytes (should be multiple of 32 for best performance)
 * @return true if buffers are equal
 */
[[nodiscard]] inline bool MemoryCompareAVX2(
    const uint8_t* a, 
    const uint8_t* b, 
    size_t size
) noexcept {
    size_t i = 0;
    
    // Process 32 bytes at a time with AVX2
    for (; i + 32 <= size; i += 32) {
        __m256i va = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(a + i));
        __m256i vb = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(b + i));
        __m256i cmp = _mm256_cmpeq_epi8(va, vb);
        if (_mm256_movemask_epi8(cmp) != -1) {
            return false;
        }
    }
    
    // Handle remaining bytes
    for (; i < size; ++i) {
        if (a[i] != b[i]) return false;
    }
    
    return true;
}

/**
 * @brief Find first occurrence of a byte using AVX2
 * @param data Buffer to search
 * @param size Buffer size
 * @param byte Byte to find
 * @return Index of first occurrence, or size if not found
 */
[[nodiscard]] inline size_t FindByteAVX2(
    const uint8_t* data,
    size_t size,
    uint8_t byte
) noexcept {
    __m256i pattern = _mm256_set1_epi8(static_cast<char>(byte));
    size_t i = 0;
    
    for (; i + 32 <= size; i += 32) {
        __m256i chunk = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(data + i));
        __m256i cmp = _mm256_cmpeq_epi8(chunk, pattern);
        int mask = _mm256_movemask_epi8(cmp);
        if (mask != 0) {
            return i + __builtin_ctz(mask);
        }
    }
    
    // Handle remaining bytes
    for (; i < size; ++i) {
        if (data[i] == byte) return i;
    }
    
    return size;
}

/**
 * @brief XOR two buffers using AVX2
 * @param dst Destination buffer (also first operand)
 * @param src Source buffer (second operand)
 * @param size Size in bytes
 */
inline void XorBuffersAVX2(
    uint8_t* dst,
    const uint8_t* src,
    size_t size
) noexcept {
    size_t i = 0;
    
    for (; i + 32 <= size; i += 32) {
        __m256i vdst = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(dst + i));
        __m256i vsrc = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(src + i));
        __m256i result = _mm256_xor_si256(vdst, vsrc);
        _mm256_storeu_si256(reinterpret_cast<__m256i*>(dst + i), result);
    }
    
    for (; i < size; ++i) {
        dst[i] ^= src[i];
    }
}

/**
 * @brief Convert bytes to hexadecimal string using SIMD
 * @param data Input bytes
 * @param size Number of bytes
 * @param output Output buffer (must be 2*size bytes)
 */
inline void BytesToHexSIMD(
    const uint8_t* data,
    size_t size,
    char* output
) noexcept {
    static const char hexChars[] = "0123456789abcdef";
    
    // For now, use scalar implementation
    // TODO: Implement SIMD version using pshufb
    for (size_t i = 0; i < size; ++i) {
        output[i * 2] = hexChars[data[i] >> 4];
        output[i * 2 + 1] = hexChars[data[i] & 0x0F];
    }
}

/**
 * @brief Calculate population count (number of 1 bits)
 * @param data Buffer
 * @param size Size in bytes
 * @return Number of set bits
 */
[[nodiscard]] inline size_t PopCount(
    const uint8_t* data,
    size_t size
) noexcept {
    size_t count = 0;
    size_t i = 0;
    
    // Process 8 bytes at a time
    for (; i + 8 <= size; i += 8) {
        uint64_t val;
        std::memcpy(&val, data + i, 8);
#if defined(_MSC_VER)
        count += __popcnt64(val);
#else
        count += __builtin_popcountll(val);
#endif
    }
    
    // Handle remaining bytes
    for (; i < size; ++i) {
#if defined(_MSC_VER)
        count += __popcnt(data[i]);
#else
        count += __builtin_popcount(data[i]);
#endif
    }
    
    return count;
}

}  // namespace simd
}  // namespace antivirus
