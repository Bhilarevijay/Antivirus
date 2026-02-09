/**
 * @file IGpuCompute.hpp
 * @brief Abstract interface for GPU-accelerated operations
 * 
 * Provides abstraction layer for GPU operations, allowing
 * CUDA/OpenCL implementations and CPU fallback.
 */

#pragma once

#include "antivirus/core/Types.hpp"
#include <memory>
#include <span>
#include <vector>

namespace antivirus {

/**
 * @enum GpuBackend
 * @brief Available GPU compute backends
 */
enum class GpuBackend : uint8_t {
    None,       ///< No GPU available (CPU fallback)
    CUDA,       ///< NVIDIA CUDA
    OpenCL,     ///< OpenCL (cross-platform)
    DirectCompute   ///< Windows DirectCompute
};

/**
 * @struct GpuInfo
 * @brief GPU device information
 */
struct GpuInfo {
    std::string name;
    std::string vendor;
    GpuBackend backend{GpuBackend::None};
    size_t totalMemory{0};
    size_t freeMemory{0};
    uint32_t computeUnits{0};
    bool available{false};
};

/**
 * @interface IGpuCompute
 * @brief GPU compute abstraction interface
 * 
 * All methods are designed to be non-blocking where possible.
 * Results are returned via output parameters or futures.
 */
class IGpuCompute {
public:
    virtual ~IGpuCompute() = default;
    
    /**
     * @brief Check if GPU is available and initialized
     */
    [[nodiscard]] virtual bool IsAvailable() const noexcept = 0;
    
    /**
     * @brief Get GPU device information
     */
    [[nodiscard]] virtual GpuInfo GetDeviceInfo() const = 0;
    
    /**
     * @brief Get the backend type
     */
    [[nodiscard]] virtual GpuBackend GetBackend() const noexcept = 0;
    
    /**
     * @brief Compute SHA-256 hashes for multiple buffers
     * @param buffers Vector of input buffers
     * @return Vector of SHA-256 hashes
     */
    [[nodiscard]] virtual std::vector<SHA256Hash> ComputeSHA256Batch(
        const std::vector<std::span<const uint8_t>>& buffers
    ) = 0;
    
    /**
     * @brief Compute MD5 hashes for multiple buffers
     */
    [[nodiscard]] virtual std::vector<MD5Hash> ComputeMD5Batch(
        const std::vector<std::span<const uint8_t>>& buffers
    ) = 0;
    
    /**
     * @brief Search for patterns in multiple buffers
     * @param buffers Data buffers to search
     * @param patterns Patterns to search for
     * @return Vector of (buffer_index, pattern_index, offset) for matches
     */
    [[nodiscard]] virtual std::vector<std::tuple<size_t, size_t, size_t>>
    SearchPatternsBatch(
        const std::vector<std::span<const uint8_t>>& buffers,
        const std::vector<std::span<const uint8_t>>& patterns
    ) = 0;
    
    /**
     * @brief Synchronize all pending GPU operations
     */
    virtual void Synchronize() = 0;

protected:
    IGpuCompute() = default;
};

using IGpuComputePtr = std::shared_ptr<IGpuCompute>;

}  // namespace antivirus
