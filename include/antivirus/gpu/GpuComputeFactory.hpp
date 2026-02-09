/**
 * @file GpuComputeFactory.hpp
 * @brief Factory for GPU compute implementations
 */

#pragma once

#include "antivirus/gpu/IGpuCompute.hpp"
#include "antivirus/logging/ILogger.hpp"

namespace antivirus {

/**
 * @class GpuComputeFactory
 * @brief Factory pattern for GPU backend selection
 * 
 * Auto-detects available GPU backends and creates appropriate
 * implementation. Falls back to CPU if no GPU available.
 */
class GpuComputeFactory {
public:
    /**
     * @brief Create best available GPU compute implementation
     * @param logger Logger for diagnostics
     * @param preferredBackend Preferred backend (None = auto-detect)
     * @return GPU compute implementation
     */
    [[nodiscard]] static IGpuComputePtr Create(
        std::shared_ptr<ILogger> logger,
        GpuBackend preferredBackend = GpuBackend::None
    );
    
    /**
     * @brief Detect available backends
     * @return Vector of available backends
     */
    [[nodiscard]] static std::vector<GpuBackend> DetectAvailableBackends();
    
    /**
     * @brief Check if CUDA is available
     */
    [[nodiscard]] static bool IsCudaAvailable();
    
    /**
     * @brief Check if OpenCL is available
     */
    [[nodiscard]] static bool IsOpenCLAvailable();
    
    /**
     * @brief Create CPU fallback implementation
     */
    [[nodiscard]] static IGpuComputePtr CreateCpuFallback(
        std::shared_ptr<ILogger> logger
    );
};

}  // namespace antivirus
