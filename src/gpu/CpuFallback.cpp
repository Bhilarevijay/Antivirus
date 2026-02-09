/**
 * @file CpuFallback.cpp
 * @brief CPU implementation of GPU compute interface
 */

#include "antivirus/gpu/CpuFallback.hpp"
#include "antivirus/detection/HashEngine.hpp"
#include "antivirus/utils/SIMDUtils.hpp"

namespace antivirus {

CpuFallback::CpuFallback(std::shared_ptr<ILogger> logger)
    : m_logger(std::move(logger))
{
    m_logger->Info("GPU compute: Using CPU fallback");
}

bool CpuFallback::IsAvailable() const noexcept {
    return true;  // CPU is always available
}

GpuInfo CpuFallback::GetDeviceInfo() const {
    GpuInfo info;
    info.name = "CPU Fallback";
    info.vendor = "N/A";
    info.backend = GpuBackend::None;
    info.available = true;
    return info;
}

GpuBackend CpuFallback::GetBackend() const noexcept {
    return GpuBackend::None;
}

std::vector<SHA256Hash> CpuFallback::ComputeSHA256Batch(
    const std::vector<std::span<const uint8_t>>& buffers
) {
    std::vector<SHA256Hash> results;
    results.reserve(buffers.size());
    
    HashEngine engine;
    
    for (const auto& buffer : buffers) {
        results.push_back(engine.ComputeSHA256(buffer));
    }
    
    return results;
}

std::vector<MD5Hash> CpuFallback::ComputeMD5Batch(
    const std::vector<std::span<const uint8_t>>& buffers
) {
    std::vector<MD5Hash> results;
    results.reserve(buffers.size());
    
    HashEngine engine;
    
    for (const auto& buffer : buffers) {
        results.push_back(engine.ComputeMD5(buffer));
    }
    
    return results;
}

std::vector<std::tuple<size_t, size_t, size_t>> CpuFallback::SearchPatternsBatch(
    const std::vector<std::span<const uint8_t>>& buffers,
    const std::vector<std::span<const uint8_t>>& patterns
) {
    std::vector<std::tuple<size_t, size_t, size_t>> matches;
    
    for (size_t bi = 0; bi < buffers.size(); ++bi) {
        const auto& buffer = buffers[bi];
        
        for (size_t pi = 0; pi < patterns.size(); ++pi) {
            const auto& pattern = patterns[pi];
            
            if (pattern.size() > buffer.size()) {
                continue;
            }
            
            // Use SIMD-accelerated search if available
            for (size_t offset = 0; offset <= buffer.size() - pattern.size(); ++offset) {
                bool match = true;
                
                if (simd::HasAVX2() && pattern.size() >= 32) {
                    match = simd::MemoryCompareAVX2(
                        buffer.data() + offset,
                        pattern.data(),
                        pattern.size()
                    );
                } else {
                    for (size_t i = 0; i < pattern.size(); ++i) {
                        if (buffer[offset + i] != pattern[i]) {
                            match = false;
                            break;
                        }
                    }
                }
                
                if (match) {
                    matches.emplace_back(bi, pi, offset);
                }
            }
        }
    }
    
    return matches;
}

void CpuFallback::Synchronize() {
    // No-op for CPU
}

}  // namespace antivirus
