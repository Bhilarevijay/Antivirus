/**
 * @file CudaCompute.cu
 * @brief CUDA GPU compute implementation
 * 
 * GPU-accelerated SHA-256 hashing and pattern matching.
 * Targets all NVIDIA GPUs with compute capability >= 5.0 (Maxwell+).
 * Uses PTX JIT compilation for forward compatibility with future GPUs.
 */

#ifdef HAS_CUDA

#include "antivirus/gpu/CudaCompute.hpp"
#include <cuda_runtime.h>
#include <device_launch_parameters.h>
#include <cstring>
#include <algorithm>
#include <stdexcept>

namespace antivirus {

// ============================================================================
// CUDA Error Checking
// ============================================================================

#define CUDA_CHECK(call) do {                                                \
    cudaError_t err = (call);                                                \
    if (err != cudaSuccess) {                                                \
        throw std::runtime_error(                                            \
            std::string("CUDA error: ") + cudaGetErrorString(err) +          \
            " at " + __FILE__ + ":" + std::to_string(__LINE__));             \
    }                                                                        \
} while(0)

// ============================================================================
// SHA-256 Constants (device memory)
// ============================================================================

__constant__ uint32_t d_K[64] = {
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

// ============================================================================
// SHA-256 Device Functions
// ============================================================================

__device__ __forceinline__ uint32_t rotr(uint32_t x, int n) {
    return (x >> n) | (x << (32 - n));
}

__device__ __forceinline__ uint32_t Ch(uint32_t e, uint32_t f, uint32_t g) {
    return (e & f) ^ (~e & g);
}

__device__ __forceinline__ uint32_t Maj(uint32_t a, uint32_t b, uint32_t c) {
    return (a & b) ^ (a & c) ^ (b & c);
}

__device__ __forceinline__ uint32_t Sigma0(uint32_t a) {
    return rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
}

__device__ __forceinline__ uint32_t Sigma1(uint32_t e) {
    return rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
}

__device__ __forceinline__ uint32_t sigma0(uint32_t x) {
    return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
}

__device__ __forceinline__ uint32_t sigma1(uint32_t x) {
    return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
}

__device__ __forceinline__ uint32_t toBE32(const uint8_t* p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | 
           ((uint32_t)p[2] << 8)  | (uint32_t)p[3];
}

// ============================================================================
// SHA-256 CUDA Kernel
// ============================================================================

/**
 * @brief GPU kernel: compute SHA-256 for each buffer
 * 
 * Each thread computes SHA-256 for one buffer.
 * Handles padding and multi-block messages internally.
 */
__global__ void sha256_kernel(
    const uint8_t* __restrict__ allData,     // All buffers concatenated
    const size_t*  __restrict__ offsets,      // Start offset of each buffer
    const size_t*  __restrict__ lengths,      // Length of each buffer
    uint8_t*       __restrict__ hashes,       // Output: 32 bytes per buffer
    int numBuffers
) {
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= numBuffers) return;
    
    const uint8_t* data = allData + offsets[idx];
    size_t len = lengths[idx];
    uint8_t* outHash = hashes + idx * 32;
    
    // Initial hash values
    uint32_t h0 = 0x6a09e667, h1 = 0xbb67ae85;
    uint32_t h2 = 0x3c6ef372, h3 = 0xa54ff53a;
    uint32_t h4 = 0x510e527f, h5 = 0x9b05688c;
    uint32_t h6 = 0x1f83d9ab, h7 = 0x5be0cd19;
    
    // Process full 64-byte blocks
    size_t fullBlocks = len / 64;
    
    for (size_t block = 0; block < fullBlocks; ++block) {
        const uint8_t* blk = data + block * 64;
        uint32_t W[64];
        
        // Load from message
        for (int i = 0; i < 16; ++i) {
            W[i] = toBE32(blk + i * 4);
        }
        for (int i = 16; i < 64; ++i) {
            W[i] = sigma1(W[i-2]) + W[i-7] + sigma0(W[i-15]) + W[i-16];
        }
        
        uint32_t a=h0, b=h1, c=h2, d=h3, e=h4, f=h5, g=h6, h=h7;
        
        for (int i = 0; i < 64; ++i) {
            uint32_t T1 = h + Sigma1(e) + Ch(e,f,g) + d_K[i] + W[i];
            uint32_t T2 = Sigma0(a) + Maj(a,b,c);
            h=g; g=f; f=e; e=d+T1; d=c; c=b; b=a; a=T1+T2;
        }
        
        h0+=a; h1+=b; h2+=c; h3+=d; h4+=e; h5+=f; h6+=g; h7+=h;
    }
    
    // Handle remaining bytes + padding
    // Create padded final block(s)
    uint8_t padBlock[128]; // Max 2 blocks for padding
    size_t remaining = len % 64;
    size_t padLen = 0;
    
    // Copy remaining bytes
    for (size_t i = 0; i < remaining; ++i) {
        padBlock[i] = data[fullBlocks * 64 + i];
    }
    padLen = remaining;
    
    // Add 0x80 byte
    padBlock[padLen++] = 0x80;
    
    // Determine if we need 1 or 2 padding blocks
    int padBlocks = (padLen + 8 > 64) ? 2 : 1;
    
    // Zero fill
    for (size_t i = padLen; i < (size_t)(padBlocks * 64); ++i) {
        padBlock[i] = 0;
    }
    
    // Append length in bits (big-endian, 64-bit)
    uint64_t bitLen = (uint64_t)len * 8;
    int endOffset = padBlocks * 64 - 8;
    padBlock[endOffset + 0] = (uint8_t)(bitLen >> 56);
    padBlock[endOffset + 1] = (uint8_t)(bitLen >> 48);
    padBlock[endOffset + 2] = (uint8_t)(bitLen >> 40);
    padBlock[endOffset + 3] = (uint8_t)(bitLen >> 32);
    padBlock[endOffset + 4] = (uint8_t)(bitLen >> 24);
    padBlock[endOffset + 5] = (uint8_t)(bitLen >> 16);
    padBlock[endOffset + 6] = (uint8_t)(bitLen >> 8);
    padBlock[endOffset + 7] = (uint8_t)(bitLen);
    
    // Process padding block(s)
    for (int pb = 0; pb < padBlocks; ++pb) {
        const uint8_t* blk = padBlock + pb * 64;
        uint32_t W[64];
        
        for (int i = 0; i < 16; ++i) {
            W[i] = toBE32(blk + i * 4);
        }
        for (int i = 16; i < 64; ++i) {
            W[i] = sigma1(W[i-2]) + W[i-7] + sigma0(W[i-15]) + W[i-16];
        }
        
        uint32_t a=h0, b=h1, c=h2, d=h3, e=h4, f=h5, g=h6, h=h7;
        
        for (int i = 0; i < 64; ++i) {
            uint32_t T1 = h + Sigma1(e) + Ch(e,f,g) + d_K[i] + W[i];
            uint32_t T2 = Sigma0(a) + Maj(a,b,c);
            h=g; g=f; f=e; e=d+T1; d=c; c=b; b=a; a=T1+T2;
        }
        
        h0+=a; h1+=b; h2+=c; h3+=d; h4+=e; h5+=f; h6+=g; h7+=h;
    }
    
    // Write output hash (big-endian)
    auto writeU32BE = [](uint8_t* dst, uint32_t val) {
        dst[0] = (uint8_t)(val >> 24);
        dst[1] = (uint8_t)(val >> 16);
        dst[2] = (uint8_t)(val >> 8);
        dst[3] = (uint8_t)(val);
    };
    
    writeU32BE(outHash +  0, h0);
    writeU32BE(outHash +  4, h1);
    writeU32BE(outHash +  8, h2);
    writeU32BE(outHash + 12, h3);
    writeU32BE(outHash + 16, h4);
    writeU32BE(outHash + 20, h5);
    writeU32BE(outHash + 24, h6);
    writeU32BE(outHash + 28, h7);
}

// ============================================================================
// Pattern Matching CUDA Kernel
// ============================================================================

/**
 * @brief GPU kernel: search for all patterns in all buffers
 * 
 * Each thread handles one (buffer, position) pair and tests all patterns.
 * Results are written atomically to a shared match counter.
 */
__global__ void pattern_search_kernel(
    const uint8_t* __restrict__ allBuffers,
    const size_t*  __restrict__ bufOffsets,
    const size_t*  __restrict__ bufLengths,
    int numBuffers,
    const uint8_t* __restrict__ allPatterns,
    const size_t*  __restrict__ patOffsets,
    const size_t*  __restrict__ patLengths,
    int numPatterns,
    // Output
    size_t* __restrict__ matchBufIdx,
    size_t* __restrict__ matchPatIdx,
    size_t* __restrict__ matchOffset,
    int*    __restrict__ matchCount,
    int maxMatches
) {
    // Global thread index maps to (bufferIndex, position)
    int globalIdx = blockIdx.x * blockDim.x + threadIdx.x;
    
    // Compute which buffer and position this thread handles
    int bufIdx = 0;
    int pos = globalIdx;
    
    for (int b = 0; b < numBuffers; ++b) {
        if (pos < (int)bufLengths[b]) {
            bufIdx = b;
            break;
        }
        pos -= (int)bufLengths[b];
        if (b == numBuffers - 1) return; // out of range
    }
    
    if (pos < 0) return;
    
    const uint8_t* buf = allBuffers + bufOffsets[bufIdx];
    size_t bufLen = bufLengths[bufIdx];
    
    // Test each pattern at this position
    for (int p = 0; p < numPatterns; ++p) {
        size_t patLen = patLengths[p];
        if ((size_t)pos + patLen > bufLen) continue;
        
        const uint8_t* pat = allPatterns + patOffsets[p];
        
        // Compare pattern bytes
        bool match = true;
        for (size_t i = 0; i < patLen; ++i) {
            if (buf[pos + i] != pat[i]) {
                match = false;
                break;
            }
        }
        
        if (match) {
            int slot = atomicAdd(matchCount, 1);
            if (slot < maxMatches) {
                matchBufIdx[slot] = bufIdx;
                matchPatIdx[slot] = p;
                matchOffset[slot] = pos;
            }
        }
    }
}

// ============================================================================
// CudaCompute::Impl (PIMPL)
// ============================================================================

class CudaCompute::Impl {
public:
    int deviceId{0};
    cudaDeviceProp deviceProps{};
    cudaStream_t stream{nullptr};
    
    Impl() = default;
    
    ~Impl() {
        if (stream) {
            cudaStreamDestroy(stream);
            stream = nullptr;
        }
    }
};

// ============================================================================
// CudaCompute Implementation
// ============================================================================

CudaCompute::CudaCompute(std::shared_ptr<ILogger> logger)
    : m_logger(std::move(logger))
    , m_impl(std::make_unique<Impl>())
{
    // Detect CUDA devices
    int deviceCount = 0;
    cudaError_t err = cudaGetDeviceCount(&deviceCount);
    
    if (err != cudaSuccess || deviceCount == 0) {
        m_logger->Info("CUDA: No compatible GPU devices found");
        m_available = false;
        return;
    }
    
    // Find best device (highest compute capability)
    int bestDevice = 0;
    int bestScore = 0;
    
    for (int i = 0; i < deviceCount; ++i) {
        cudaDeviceProp props;
        cudaGetDeviceProperties(&props, i);
        
        int score = props.major * 100 + props.minor * 10 + 
                    (int)(props.totalGlobalMem / (1024ULL * 1024ULL * 1024ULL));
        
        if (score > bestScore) {
            bestScore = score;
            bestDevice = i;
        }
    }
    
    m_impl->deviceId = bestDevice;
    CUDA_CHECK(cudaSetDevice(bestDevice));
    CUDA_CHECK(cudaGetDeviceProperties(&m_impl->deviceProps, bestDevice));
    CUDA_CHECK(cudaStreamCreate(&m_impl->stream));
    
    // Check minimum compute capability (5.0 = Maxwell)
    auto& props = m_impl->deviceProps;
    if (props.major < 5) {
        m_logger->Warn("CUDA: GPU {} has compute capability {}.{}, minimum is 5.0",
            props.name, props.major, props.minor);
        m_available = false;
        return;
    }
    
    // Populate device info
    m_deviceInfo.name = props.name;
    m_deviceInfo.vendor = "NVIDIA";
    m_deviceInfo.backend = GpuBackend::CUDA;
    m_deviceInfo.totalMemory = props.totalGlobalMem;
    m_deviceInfo.computeUnits = props.multiProcessorCount;
    m_deviceInfo.available = true;
    
    // Query free memory
    size_t freeMem = 0, totalMem = 0;
    cudaMemGetInfo(&freeMem, &totalMem);
    m_deviceInfo.freeMemory = freeMem;
    
    m_available = true;
    
    m_logger->Info("CUDA: {} (SM {}.{}, {} SMs, {} MB VRAM)",
        props.name, props.major, props.minor,
        props.multiProcessorCount,
        props.totalGlobalMem / (1024 * 1024));
}

CudaCompute::~CudaCompute() = default;

bool CudaCompute::IsAvailable() const noexcept {
    return m_available;
}

GpuInfo CudaCompute::GetDeviceInfo() const {
    return m_deviceInfo;
}

GpuBackend CudaCompute::GetBackend() const noexcept {
    return GpuBackend::CUDA;
}

std::vector<SHA256Hash> CudaCompute::ComputeSHA256Batch(
    const std::vector<std::span<const uint8_t>>& buffers
) {
    if (!m_available || buffers.empty()) {
        return {};
    }
    
    const int numBuffers = static_cast<int>(buffers.size());
    
    // Concatenate all buffers and compute offsets
    size_t totalSize = 0;
    std::vector<size_t> offsets(numBuffers);
    std::vector<size_t> lengths(numBuffers);
    
    for (int i = 0; i < numBuffers; ++i) {
        offsets[i] = totalSize;
        lengths[i] = buffers[i].size();
        totalSize += buffers[i].size();
    }
    
    // Flatten data
    std::vector<uint8_t> flatData(totalSize);
    for (int i = 0; i < numBuffers; ++i) {
        if (!buffers[i].empty()) {
            std::memcpy(flatData.data() + offsets[i], 
                       buffers[i].data(), buffers[i].size());
        }
    }
    
    // Allocate device memory
    uint8_t*  d_data = nullptr;
    size_t*   d_offsets = nullptr;
    size_t*   d_lengths = nullptr;
    uint8_t*  d_hashes = nullptr;
    
    CUDA_CHECK(cudaMalloc(&d_data, totalSize > 0 ? totalSize : 1));
    CUDA_CHECK(cudaMalloc(&d_offsets, numBuffers * sizeof(size_t)));
    CUDA_CHECK(cudaMalloc(&d_lengths, numBuffers * sizeof(size_t)));
    CUDA_CHECK(cudaMalloc(&d_hashes, numBuffers * 32));
    
    // Copy to device
    if (totalSize > 0) {
        CUDA_CHECK(cudaMemcpyAsync(d_data, flatData.data(), totalSize,
            cudaMemcpyHostToDevice, m_impl->stream));
    }
    CUDA_CHECK(cudaMemcpyAsync(d_offsets, offsets.data(), 
        numBuffers * sizeof(size_t), cudaMemcpyHostToDevice, m_impl->stream));
    CUDA_CHECK(cudaMemcpyAsync(d_lengths, lengths.data(),
        numBuffers * sizeof(size_t), cudaMemcpyHostToDevice, m_impl->stream));
    
    // Launch kernel
    int threadsPerBlock = 256;
    int blocks = (numBuffers + threadsPerBlock - 1) / threadsPerBlock;
    
    sha256_kernel<<<blocks, threadsPerBlock, 0, m_impl->stream>>>(
        d_data, d_offsets, d_lengths, d_hashes, numBuffers
    );
    
    // Copy results back
    std::vector<uint8_t> hostHashes(numBuffers * 32);
    CUDA_CHECK(cudaMemcpyAsync(hostHashes.data(), d_hashes,
        numBuffers * 32, cudaMemcpyDeviceToHost, m_impl->stream));
    
    CUDA_CHECK(cudaStreamSynchronize(m_impl->stream));
    
    // Convert to SHA256Hash array
    std::vector<SHA256Hash> results(numBuffers);
    for (int i = 0; i < numBuffers; ++i) {
        std::memcpy(results[i].data(), hostHashes.data() + i * 32, 32);
    }
    
    // Cleanup
    cudaFree(d_data);
    cudaFree(d_offsets);
    cudaFree(d_lengths);
    cudaFree(d_hashes);
    
    return results;
}

std::vector<MD5Hash> CudaCompute::ComputeMD5Batch(
    const std::vector<std::span<const uint8_t>>& buffers
) {
    // MD5 is less commonly GPU-accelerated and less security-critical
    // Fall back to CPU for MD5 (SHA-256 is the primary GPU-accelerated hash)
    // This keeps the CUDA code simpler and avoids diminishing returns
    
    // Return empty — caller should use CpuFallback for MD5
    return {};
}

std::vector<std::tuple<size_t, size_t, size_t>>
CudaCompute::SearchPatternsBatch(
    const std::vector<std::span<const uint8_t>>& buffers,
    const std::vector<std::span<const uint8_t>>& patterns
) {
    if (!m_available || buffers.empty() || patterns.empty()) {
        return {};
    }
    
    const int numBuffers = static_cast<int>(buffers.size());
    const int numPatterns = static_cast<int>(patterns.size());
    
    // Flatten buffers
    size_t totalBufSize = 0;
    std::vector<size_t> bufOffsets(numBuffers);
    std::vector<size_t> bufLengths(numBuffers);
    
    for (int i = 0; i < numBuffers; ++i) {
        bufOffsets[i] = totalBufSize;
        bufLengths[i] = buffers[i].size();
        totalBufSize += buffers[i].size();
    }
    
    std::vector<uint8_t> flatBufs(totalBufSize);
    for (int i = 0; i < numBuffers; ++i) {
        if (!buffers[i].empty()) {
            std::memcpy(flatBufs.data() + bufOffsets[i],
                       buffers[i].data(), buffers[i].size());
        }
    }
    
    // Flatten patterns
    size_t totalPatSize = 0;
    std::vector<size_t> patOffsets(numPatterns);
    std::vector<size_t> patLengths(numPatterns);
    
    for (int i = 0; i < numPatterns; ++i) {
        patOffsets[i] = totalPatSize;
        patLengths[i] = patterns[i].size();
        totalPatSize += patterns[i].size();
    }
    
    std::vector<uint8_t> flatPats(totalPatSize);
    for (int i = 0; i < numPatterns; ++i) {
        if (!patterns[i].empty()) {
            std::memcpy(flatPats.data() + patOffsets[i],
                       patterns[i].data(), patterns[i].size());
        }
    }
    
    // Total positions to check
    size_t totalPositions = totalBufSize;
    if (totalPositions == 0) return {};
    
    // Allocate device memory
    constexpr int MAX_MATCHES = 100000;
    
    uint8_t* d_bufs = nullptr;
    size_t*  d_bufOff = nullptr;
    size_t*  d_bufLen = nullptr;
    uint8_t* d_pats = nullptr;
    size_t*  d_patOff = nullptr;
    size_t*  d_patLen = nullptr;
    size_t*  d_matchBuf = nullptr;
    size_t*  d_matchPat = nullptr;
    size_t*  d_matchOff = nullptr;
    int*     d_matchCount = nullptr;
    
    CUDA_CHECK(cudaMalloc(&d_bufs, totalBufSize > 0 ? totalBufSize : 1));
    CUDA_CHECK(cudaMalloc(&d_bufOff, numBuffers * sizeof(size_t)));
    CUDA_CHECK(cudaMalloc(&d_bufLen, numBuffers * sizeof(size_t)));
    CUDA_CHECK(cudaMalloc(&d_pats, totalPatSize > 0 ? totalPatSize : 1));
    CUDA_CHECK(cudaMalloc(&d_patOff, numPatterns * sizeof(size_t)));
    CUDA_CHECK(cudaMalloc(&d_patLen, numPatterns * sizeof(size_t)));
    CUDA_CHECK(cudaMalloc(&d_matchBuf, MAX_MATCHES * sizeof(size_t)));
    CUDA_CHECK(cudaMalloc(&d_matchPat, MAX_MATCHES * sizeof(size_t)));
    CUDA_CHECK(cudaMalloc(&d_matchOff, MAX_MATCHES * sizeof(size_t)));
    CUDA_CHECK(cudaMalloc(&d_matchCount, sizeof(int)));
    
    // Zero match counter
    CUDA_CHECK(cudaMemsetAsync(d_matchCount, 0, sizeof(int), m_impl->stream));
    
    // Copy data to device
    if (totalBufSize > 0) {
        CUDA_CHECK(cudaMemcpyAsync(d_bufs, flatBufs.data(), totalBufSize,
            cudaMemcpyHostToDevice, m_impl->stream));
    }
    CUDA_CHECK(cudaMemcpyAsync(d_bufOff, bufOffsets.data(),
        numBuffers * sizeof(size_t), cudaMemcpyHostToDevice, m_impl->stream));
    CUDA_CHECK(cudaMemcpyAsync(d_bufLen, bufLengths.data(),
        numBuffers * sizeof(size_t), cudaMemcpyHostToDevice, m_impl->stream));
    if (totalPatSize > 0) {
        CUDA_CHECK(cudaMemcpyAsync(d_pats, flatPats.data(), totalPatSize,
            cudaMemcpyHostToDevice, m_impl->stream));
    }
    CUDA_CHECK(cudaMemcpyAsync(d_patOff, patOffsets.data(),
        numPatterns * sizeof(size_t), cudaMemcpyHostToDevice, m_impl->stream));
    CUDA_CHECK(cudaMemcpyAsync(d_patLen, patLengths.data(),
        numPatterns * sizeof(size_t), cudaMemcpyHostToDevice, m_impl->stream));
    
    // Launch kernel
    int threadsPerBlock = 256;
    int blocks = (static_cast<int>(totalPositions) + threadsPerBlock - 1) / threadsPerBlock;
    
    pattern_search_kernel<<<blocks, threadsPerBlock, 0, m_impl->stream>>>(
        d_bufs, d_bufOff, d_bufLen, numBuffers,
        d_pats, d_patOff, d_patLen, numPatterns,
        d_matchBuf, d_matchPat, d_matchOff, d_matchCount, MAX_MATCHES
    );
    
    // Read match count
    int hostMatchCount = 0;
    CUDA_CHECK(cudaMemcpyAsync(&hostMatchCount, d_matchCount, sizeof(int),
        cudaMemcpyDeviceToHost, m_impl->stream));
    CUDA_CHECK(cudaStreamSynchronize(m_impl->stream));
    
    // Read matches
    int resultCount = std::min(hostMatchCount, MAX_MATCHES);
    std::vector<std::tuple<size_t, size_t, size_t>> results;
    
    if (resultCount > 0) {
        std::vector<size_t> hostBuf(resultCount), hostPat(resultCount), hostOff(resultCount);
        CUDA_CHECK(cudaMemcpy(hostBuf.data(), d_matchBuf,
            resultCount * sizeof(size_t), cudaMemcpyDeviceToHost));
        CUDA_CHECK(cudaMemcpy(hostPat.data(), d_matchPat,
            resultCount * sizeof(size_t), cudaMemcpyDeviceToHost));
        CUDA_CHECK(cudaMemcpy(hostOff.data(), d_matchOff,
            resultCount * sizeof(size_t), cudaMemcpyDeviceToHost));
        
        results.reserve(resultCount);
        for (int i = 0; i < resultCount; ++i) {
            results.emplace_back(hostBuf[i], hostPat[i], hostOff[i]);
        }
    }
    
    // Cleanup
    cudaFree(d_bufs);
    cudaFree(d_bufOff);
    cudaFree(d_bufLen);
    cudaFree(d_pats);
    cudaFree(d_patOff);
    cudaFree(d_patLen);
    cudaFree(d_matchBuf);
    cudaFree(d_matchPat);
    cudaFree(d_matchOff);
    cudaFree(d_matchCount);
    
    return results;
}

void CudaCompute::Synchronize() {
    if (m_available && m_impl->stream) {
        cudaStreamSynchronize(m_impl->stream);
    }
}

}  // namespace antivirus

#endif // HAS_CUDA
