/**
 * @file CpuFallback.hpp
 * @brief CPU implementation of GPU interface
 * 
 * Provides CPU-based implementations when GPU is unavailable.
 * Uses SIMD where possible for improved performance.
 */

#pragma once

#include "antivirus/gpu/IGpuCompute.hpp"
#include "antivirus/logging/ILogger.hpp"

namespace antivirus {

/**
 * @class CpuFallback
 * @brief CPU-based implementation of IGpuCompute
 * 
 * Used when no GPU is available. Provides identical interface
 * to GPU implementations for seamless fallback.
 */
class CpuFallback final : public IGpuCompute {
public:
    explicit CpuFallback(std::shared_ptr<ILogger> logger);
    ~CpuFallback() override = default;
    
    [[nodiscard]] bool IsAvailable() const noexcept override;
    [[nodiscard]] GpuInfo GetDeviceInfo() const override;
    [[nodiscard]] GpuBackend GetBackend() const noexcept override;
    
    [[nodiscard]] std::vector<SHA256Hash> ComputeSHA256Batch(
        const std::vector<std::span<const uint8_t>>& buffers
    ) override;
    
    [[nodiscard]] std::vector<MD5Hash> ComputeMD5Batch(
        const std::vector<std::span<const uint8_t>>& buffers
    ) override;
    
    [[nodiscard]] std::vector<std::tuple<size_t, size_t, size_t>>
    SearchPatternsBatch(
        const std::vector<std::span<const uint8_t>>& buffers,
        const std::vector<std::span<const uint8_t>>& patterns
    ) override;
    
    void Synchronize() override;

private:
    std::shared_ptr<ILogger> m_logger;
};

}  // namespace antivirus
