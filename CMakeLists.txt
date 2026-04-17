cmake_minimum_required(VERSION 3.20)
project(Antivirus VERSION 1.0.0 LANGUAGES CXX)

# C++20 Standard
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Windows-specific settings
if(MSVC)
    # Apply MSVC flags only to C++ files (not CUDA .cu files)
    add_compile_options($<$<COMPILE_LANGUAGE:CXX>:/W4> $<$<COMPILE_LANGUAGE:CXX>:/permissive-> $<$<COMPILE_LANGUAGE:CXX>:/Zc:__cplusplus>)
    # Disable specific non-critical warnings (CXX only)
    add_compile_options(
        $<$<COMPILE_LANGUAGE:CXX>:/wd4324>
        $<$<COMPILE_LANGUAGE:CXX>:/wd4834>
        $<$<COMPILE_LANGUAGE:CXX>:/wd4065>
        $<$<COMPILE_LANGUAGE:CXX>:/wd4267>
    )
    add_compile_definitions(
        _WIN32_WINNT=0x0A00  # Windows 10
        UNICODE
        _UNICODE
        NOMINMAX
        _CRT_SECURE_NO_WARNINGS
    )

    # ── Static link MSVC runtime (no DLL dependencies) ──
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

    # ── Release optimizations ──
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /O2 /GL /Gy")
    set(CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} /LTCG /OPT:REF /OPT:ICF")
else()
    # For cross-compilation/syntax checking on Linux
    add_compile_options(-Wall -Wextra -Wpedantic)
endif()

# Include directories
include_directories(${CMAKE_SOURCE_DIR}/include)

# Collect source files
file(GLOB_RECURSE SOURCES "src/*.cpp")
file(GLOB_RECURSE HEADERS "include/*.hpp")

# Main executable
add_executable(antivirus ${SOURCES} ${HEADERS})

# Link Windows libraries (when building on Windows)
if(WIN32)
    target_link_libraries(antivirus
        advapi32    # ACL/security functions
        kernel32
        winhttp     # Signature updates (WinHTTP)
        bcrypt      # Cryptographic hashing (BCrypt API)
    )
endif()

# ── YARA Rule Engine ──
find_package(unofficial-libyara CONFIG QUIET)
if(unofficial-libyara_FOUND)
    target_link_libraries(antivirus unofficial::libyara::libyara)
    target_compile_definitions(antivirus PRIVATE HAS_YARA)
    message(STATUS "YARA enabled: libyara found via vcpkg")
else()
    message(STATUS "YARA not found — building without YARA rule support")
endif()

# Enable SIMD optimizations (CXX only, not CUDA)
if(MSVC)
    target_compile_options(antivirus PRIVATE $<$<COMPILE_LANGUAGE:CXX>:/arch:AVX2>)
else()
    target_compile_options(antivirus PRIVATE -mavx2 -msse4.2)
endif()

# ── CUDA GPU Acceleration ──
# Auto-detects CUDA toolkit. Use -DENABLE_CUDA=ON to force.
option(ENABLE_CUDA "Enable CUDA GPU acceleration" OFF)

if(ENABLE_CUDA)
    # CUDA 13.1 officially supports VS 2019-2022.
    # VS 18 (2026) needs --allow-unsupported-compiler to bypass the version check.
    set(CMAKE_CUDA_FLAGS "${CMAKE_CUDA_FLAGS} --allow-unsupported-compiler")

    # Find CUDA toolkit
    include(CheckLanguage)
    check_language(CUDA)
    
    if(CMAKE_CUDA_COMPILER)
        # ── Multi-architecture build: works on ALL NVIDIA GPUs ──
        # Must set BEFORE enable_language(CUDA)
        # CUDA 13.1 supports sm_75+ (Turing and newer)
        # sm_75  = Turing    (RTX 2000/GTX 1600 series, 2018+)
        # sm_80  = Ampere    (RTX 3000/A100, 2020+)
        # sm_86  = Ampere    (RTX 3050-3090 Ti)
        # sm_89  = Ada       (RTX 4000 series, 2022+)
        # sm_90  = Hopper    (H100, 2023+)
        # sm_100 = Blackwell (RTX 5000/B200, 2025+)
        set(CMAKE_CUDA_ARCHITECTURES 75 80 86 89 90 100)
        
        enable_language(CUDA)
        
        # CUDA source files
        file(GLOB CUDA_SOURCES "src/gpu/*.cu")
        target_sources(antivirus PRIVATE ${CUDA_SOURCES})
        
        # CUDA compile definition
        target_compile_definitions(antivirus PRIVATE HAS_CUDA)
        
        # C++20 for CUDA host code
        set_property(TARGET antivirus PROPERTY CUDA_STANDARD 20)
        
        # Set architectures on target explicitly too
        set_property(TARGET antivirus PROPERTY CUDA_ARCHITECTURES 75 80 86 89 90 100)
        
        # Separate compilation for device code
        set_property(TARGET antivirus PROPERTY CUDA_SEPARABLE_COMPILATION ON)
        
        # Link CUDA runtime
        find_package(CUDAToolkit REQUIRED)
        target_link_libraries(antivirus CUDA::cudart)
        
        message(STATUS "CUDA enabled: targeting SM ${CMAKE_CUDA_ARCHITECTURES}")
    else()
        message(WARNING "CUDA requested but nvcc not found. Building without GPU support.")
    endif()
endif()

# Output directory
set_target_properties(antivirus PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

# Copy signatures to build output directory (next to exe)
add_custom_command(TARGET antivirus POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory "$<TARGET_FILE_DIR:antivirus>/signatures"
    COMMAND ${CMAKE_COMMAND} -E copy_directory
        "${CMAKE_SOURCE_DIR}/signatures"
        "$<TARGET_FILE_DIR:antivirus>/signatures"
    COMMENT "Copying signature database to output directory"
)

# Copy YARA rules to build output directory
if(EXISTS "${CMAKE_SOURCE_DIR}/rules")
    add_custom_command(TARGET antivirus POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E make_directory "$<TARGET_FILE_DIR:antivirus>/rules"
        COMMAND ${CMAKE_COMMAND} -E copy_directory
            "${CMAKE_SOURCE_DIR}/rules"
            "$<TARGET_FILE_DIR:antivirus>/rules"
        COMMENT "Copying YARA rules to output directory"
    )
endif()
