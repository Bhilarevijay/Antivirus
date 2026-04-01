/**
 * @file GpuComputeFactory.cpp
 * @brief Factory for GPU backend creation
 */

#include "antivirus/gpu/GpuComputeFactory.hpp"
#include "antivirus/gpu/CpuFallback.hpp"

#ifdef HAS_CUDA
    #include "antivirus/gpu/CudaCompute.hpp"
    #include <cuda_runtime.h>
#endif

namespace antivirus {

IGpuComputePtr GpuComputeFactory::Create(
    std::shared_ptr<ILogger> logger,
    GpuBackend preferredBackend
) {
    auto backends = DetectAvailableBackends();
    
    if (preferredBackend != GpuBackend::None) {
        // Check if preferred backend is available
        for (GpuBackend backend : backends) {
            if (backend == preferredBackend) {
                switch (backend) {
#ifdef HAS_CUDA
                    case GpuBackend::CUDA:
                        return std::make_shared<CudaCompute>(logger);
#endif
                    default:
                        break;
                }
            }
        }
        
        logger->Warn("Preferred GPU backend not available, falling back");
    }
    
    // Try each available backend
    for (GpuBackend backend : backends) {
        switch (backend) {
#ifdef HAS_CUDA
            case GpuBackend::CUDA: {
                auto cuda = std::make_shared<CudaCompute>(logger);
                if (cuda->IsAvailable()) {
                    return cuda;
                }
                break;
            }
#endif
            default:
                break;
        }
    }
    
    // Fall back to CPU
    return CreateCpuFallback(logger);
}

std::vector<GpuBackend> GpuComputeFactory::DetectAvailableBackends() {
    std::vector<GpuBackend> backends;
    
    if (IsCudaAvailable()) {
        backends.push_back(GpuBackend::CUDA);
    }
    
    if (IsOpenCLAvailable()) {
        backends.push_back(GpuBackend::OpenCL);
    }
    
    return backends;
}

bool GpuComputeFactory::IsCudaAvailable() {
#ifdef HAS_CUDA
    // Check for CUDA runtime
    int deviceCount = 0;
    cudaError_t err = cudaGetDeviceCount(&deviceCount);
    return err == cudaSuccess && deviceCount > 0;
#else
    return false;
#endif
}

bool GpuComputeFactory::IsOpenCLAvailable() {
    // TODO: Implement OpenCL detection
    return false;
}

IGpuComputePtr GpuComputeFactory::CreateCpuFallback(
    std::shared_ptr<ILogger> logger
) {
    return std::make_shared<CpuFallback>(logger);
}

}  // namespace antivirus
