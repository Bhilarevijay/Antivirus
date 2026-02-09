/**
 * @file CudaCompute.hpp
 * @brief CUDA-based GPU compute implementation (stub)
 * 
 * Full CUDA implementation requires CUDA SDK. This header
 * defines the interface; implementation would be in .cu files.
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
 * Provides GPU acceleration on NVIDIA GPUs using CUDA.
 * Requires CUDA SDK and compatible GPU.
 */
class CudaCompute final : public IGpuCompute {
public:
    explicit CudaCompute(std::shared_ptr<ILogger> logger);
    ~CudaCompute() override;
    
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
};

}  // namespace antivirus

#endif // HAS_CUDA
