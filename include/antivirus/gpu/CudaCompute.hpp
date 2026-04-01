/**
 * @file CudaCompute.hpp
 * @brief CUDA-based GPU compute implementation
 * 
 * Provides GPU acceleration on any NVIDIA GPU (Maxwell sm_50+).
 * Uses multi-architecture builds + PTX JIT for forward compatibility.
 */

#pragma once

#include "antivirus/gpu/IGpuCompute.hpp"
#include "antivirus/logging/ILogger.hpp"

#ifdef HAS_CUDA

namespace antivirus {

/**
 * @class CudaCompute
 * @brief NVIDIA CUDA-based implementation of IGpuCompute
 * 
 * Provides GPU acceleration on any NVIDIA GPU with compute capability >= 5.0.
 * Automatically detects the best GPU device at runtime.
 */
class CudaCompute final : public IGpuCompute {
public:
    explicit CudaCompute(std::shared_ptr<ILogger> logger);
    ~CudaCompute() override;
    
    // Non-copyable, non-movable
    CudaCompute(const CudaCompute&) = delete;
    CudaCompute& operator=(const CudaCompute&) = delete;
    
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
    class Impl;
    std::unique_ptr<Impl> m_impl;
    std::shared_ptr<ILogger> m_logger;
    bool m_available{false};
    GpuInfo m_deviceInfo;
};

}  // namespace antivirus

#endif // HAS_CUDA
