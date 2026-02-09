/**
 * @file MemoryPool.hpp
 * @brief Fixed-size block memory pool for reduced heap fragmentation
 * 
 * Custom allocator that pre-allocates memory blocks for efficient
 * allocation/deallocation of fixed-size objects.
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>
#include <mutex>
#include <atomic>

namespace antivirus {

/**
 * @class MemoryPool
 * @brief Thread-safe fixed-size block allocator
 * 
 * Benefits:
 * - Reduced heap fragmentation
 * - O(1) allocation/deallocation
 * - Cache-friendly contiguous memory
 * - Thread-safe with minimal locking
 * 
 * @tparam T Object type to allocate
 * @tparam BlocksPerChunk Number of blocks per memory chunk
 */
template<typename T, size_t BlocksPerChunk = 1024>
class MemoryPool {
public:
    MemoryPool() {
        AllocateChunk();
    }
    
    ~MemoryPool() = default;
    
    // Non-copyable
    MemoryPool(const MemoryPool&) = delete;
    MemoryPool& operator=(const MemoryPool&) = delete;
    
    /**
     * @brief Allocate a block from the pool
     * @return Pointer to allocated memory
     */
    [[nodiscard]] T* Allocate() {
        std::lock_guard<std::mutex> lock(m_mutex);
        
        if (m_freeList.empty()) {
            AllocateChunk();
        }
        
        T* ptr = m_freeList.back();
        m_freeList.pop_back();
        ++m_allocatedCount;
        return ptr;
    }
    
    /**
     * @brief Return a block to the pool
     * @param ptr Pointer to deallocate
     */
    void Deallocate(T* ptr) {
        if (ptr == nullptr) return;
        
        std::lock_guard<std::mutex> lock(m_mutex);
        m_freeList.push_back(ptr);
        --m_allocatedCount;
    }
    
    /**
     * @brief Construct an object in-place
     * @param args Constructor arguments
     * @return Pointer to constructed object
     */
    template<typename... Args>
    [[nodiscard]] T* Construct(Args&&... args) {
        T* ptr = Allocate();
        new (ptr) T(std::forward<Args>(args)...);
        return ptr;
    }
    
    /**
     * @brief Destroy and deallocate an object
     * @param ptr Object to destroy
     */
    void Destroy(T* ptr) {
        if (ptr == nullptr) return;
        ptr->~T();
        Deallocate(ptr);
    }
    
    /**
     * @brief Get number of allocated blocks
     */
    [[nodiscard]] size_t GetAllocatedCount() const noexcept {
        return m_allocatedCount.load();
    }
    
    /**
     * @brief Get total capacity (allocated chunks * blocks per chunk)
     */
    [[nodiscard]] size_t GetCapacity() const noexcept {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_chunks.size() * BlocksPerChunk;
    }

private:
    static constexpr size_t BLOCK_SIZE = sizeof(T) >= sizeof(void*) 
        ? sizeof(T) 
        : sizeof(void*);
    
    static constexpr size_t ALIGNMENT = alignof(T) >= alignof(std::max_align_t)
        ? alignof(T)
        : alignof(std::max_align_t);
    
    struct alignas(ALIGNMENT) Block {
        std::byte data[BLOCK_SIZE];
    };
    
    void AllocateChunk() {
        auto chunk = std::make_unique<std::array<Block, BlocksPerChunk>>();
        
        for (size_t i = 0; i < BlocksPerChunk; ++i) {
            m_freeList.push_back(reinterpret_cast<T*>(&(*chunk)[i]));
        }
        
        m_chunks.push_back(std::move(chunk));
    }
    
    mutable std::mutex m_mutex;
    std::vector<T*> m_freeList;
    std::vector<std::unique_ptr<std::array<Block, BlocksPerChunk>>> m_chunks;
    std::atomic<size_t> m_allocatedCount{0};
};

/**
 * @class PoolAllocator
 * @brief STL-compatible allocator using MemoryPool
 */
template<typename T, size_t BlocksPerChunk = 1024>
class PoolAllocator {
public:
    using value_type = T;
    
    explicit PoolAllocator(MemoryPool<T, BlocksPerChunk>& pool) 
        : m_pool(&pool) {}
    
    template<typename U>
    PoolAllocator(const PoolAllocator<U, BlocksPerChunk>& other) 
        : m_pool(reinterpret_cast<MemoryPool<T, BlocksPerChunk>*>(other.m_pool)) {}
    
    [[nodiscard]] T* allocate(size_t n) {
        if (n != 1) {
            throw std::bad_alloc();
        }
        return m_pool->Allocate();
    }
    
    void deallocate(T* ptr, size_t) {
        m_pool->Deallocate(ptr);
    }
    
private:
    MemoryPool<T, BlocksPerChunk>* m_pool;
    
    template<typename U, size_t B>
    friend class PoolAllocator;
};

}  // namespace antivirus
