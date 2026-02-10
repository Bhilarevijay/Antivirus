cmake_minimum_required(VERSION 3.20)
project(Antivirus VERSION 1.0.0 LANGUAGES CXX)

# C++20 Standard
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Windows-specific settings
if(MSVC)
    add_compile_options(/W4 /permissive- /Zc:__cplusplus)
    # Disable specific non-critical warnings
    add_compile_options(
        /wd4324  # structure padded due to alignment specifier
        /wd4834  # discarding return value of [[nodiscard]]
        /wd4065  # switch contains default but no case labels
        /wd4267  # conversion from size_t to unsigned int
    )
    add_compile_definitions(
        _WIN32_WINNT=0x0A00  # Windows 10
        UNICODE
        _UNICODE
        NOMINMAX
        _CRT_SECURE_NO_WARNINGS
    )
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
        advapi32  # For ACL/security functions
        kernel32
    )
endif()

# Enable SIMD optimizations
if(MSVC)
    target_compile_options(antivirus PRIVATE /arch:AVX2)
else()
    target_compile_options(antivirus PRIVATE -mavx2 -msse4.2)
endif()

# Optional: CUDA support
option(ENABLE_CUDA "Enable CUDA GPU acceleration" OFF)
if(ENABLE_CUDA)
    enable_language(CUDA)
    target_compile_definitions(antivirus PRIVATE HAS_CUDA)
endif()

# Output directory
set_target_properties(antivirus PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)
