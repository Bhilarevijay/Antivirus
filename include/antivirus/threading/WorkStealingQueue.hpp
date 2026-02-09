/**
 * @file WorkStealingQueue.hpp
 * @brief Lock-free work-stealing deque for thread pool
 * 
 * Implementation of Chase-Lev work-stealing deque for balanced
 * task distribution across worker threads.
 */

#pragma once

#include <atomic>
#include <memory>
#include <vector>
#include <optional>

namespace antivirus {

/**
 * @class WorkStealingQueue
 * @brief Single-producer multi-consumer work-stealing deque
 * 
 * Based on the Chase-Lev algorithm:
 * - Owner pushes/pops from the bottom (LIFO for locality)
 * - Thieves steal from the top (FIFO)
 * - Lock-free using atomic operations
 * 
 * @tparam T Work item type
 */
template<typename T>
class WorkStealingQueue {
public:
    static constexpr size_t DEFAULT_CAPACITY = 4096;
    
    explicit WorkStealingQueue(size_t capacity = DEFAULT_CAPACITY)
        : m_capacity(capacity)
        , m_mask(capacity - 1)
        , m_buffer(std::make_unique<std::atomic<T*>[]>(capacity))
        , m_top(0)
        , m_bottom(0)
    {
        // Capacity must be power of 2
        assert((capacity & (capacity - 1)) == 0);
        
        for (size_t i = 0; i < capacity; ++i) {
            m_buffer[i].store(nullptr, std::memory_order_relaxed);
        }
    }
    
    ~WorkStealingQueue() {
        // Clean up any remaining items
        while (auto item = TryPop()) {
            delete *item;
        }
    }
    
    // Non-copyable, non-movable
    WorkStealingQueue(const WorkStealingQueue&) = delete;
    WorkStealingQueue& operator=(const WorkStealingQueue&) = delete;
    
    /**
     * @brief Push an item (called by owner thread only)
     * @param item Item to push
     * @return true if successful
     */
    bool Push(T* item) {
        size_t bottom = m_bottom.load(std::memory_order_relaxed);
        size_t top = m_top.load(std::memory_order_acquire);
        
        if (bottom - top >= m_capacity) {
            // Queue is full
            return false;
        }
        
        m_buffer[bottom & m_mask].store(item, std::memory_order_relaxed);
        std::atomic_thread_fence(std::memory_order_release);
        m_bottom.store(bottom + 1, std::memory_order_relaxed);
        return true;
    }
    
    /**
     * @brief Pop an item (called by owner thread only)
     * @return Item if available, nullopt if empty
     */
    std::optional<T*> TryPop() {
        size_t bottom = m_bottom.load(std::memory_order_relaxed) - 1;
        m_bottom.store(bottom, std::memory_order_relaxed);
        std::atomic_thread_fence(std::memory_order_seq_cst);
        size_t top = m_top.load(std::memory_order_relaxed);
        
        if (static_cast<ptrdiff_t>(bottom - top) < 0) {
            // Queue was empty
            m_bottom.store(bottom + 1, std::memory_order_relaxed);
            return std::nullopt;
        }
        
        T* item = m_buffer[bottom & m_mask].load(std::memory_order_relaxed);
        
        if (bottom != top) {
            // More than one item, no race possible
            return item;
        }
        
        // Last item, race with stealers
        if (!m_top.compare_exchange_strong(top, top + 1,
                std::memory_order_seq_cst, std::memory_order_relaxed)) {
            // Lost the race
            m_bottom.store(bottom + 1, std::memory_order_relaxed);
            return std::nullopt;
        }
        
        m_bottom.store(bottom + 1, std::memory_order_relaxed);
        return item;
    }
    
    /**
     * @brief Steal an item (called by other threads)
     * @return Item if available, nullopt if empty
     */
    std::optional<T*> TrySteal() {
        size_t top = m_top.load(std::memory_order_acquire);
        std::atomic_thread_fence(std::memory_order_seq_cst);
        size_t bottom = m_bottom.load(std::memory_order_acquire);
        
        if (static_cast<ptrdiff_t>(bottom - top) <= 0) {
            // Queue is empty
            return std::nullopt;
        }
        
        T* item = m_buffer[top & m_mask].load(std::memory_order_relaxed);
        
        if (!m_top.compare_exchange_strong(top, top + 1,
                std::memory_order_seq_cst, std::memory_order_relaxed)) {
            // Lost the race
            return std::nullopt;
        }
        
        return item;
    }
    
    /**
     * @brief Check if queue is empty (approximate)
     */
    [[nodiscard]] bool IsEmpty() const noexcept {
        size_t top = m_top.load(std::memory_order_relaxed);
        size_t bottom = m_bottom.load(std::memory_order_relaxed);
        return bottom <= top;
    }
    
    /**
     * @brief Get approximate size
     */
    [[nodiscard]] size_t Size() const noexcept {
        size_t top = m_top.load(std::memory_order_relaxed);
        size_t bottom = m_bottom.load(std::memory_order_relaxed);
        return bottom > top ? bottom - top : 0;
    }

private:
    const size_t m_capacity;
    const size_t m_mask;
    std::unique_ptr<std::atomic<T*>[]> m_buffer;
    
    // Separate cache lines
    alignas(64) std::atomic<size_t> m_top;
    alignas(64) std::atomic<size_t> m_bottom;
};

}  // namespace antivirus
