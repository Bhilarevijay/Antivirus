/**
 * @file LockFreeQueue.hpp
 * @brief Lock-free MPMC queue for high-performance task distribution
 * 
 * Uses atomic operations for thread-safe enqueue/dequeue without locks.
 * Suitable for producer-consumer patterns in scanning pipeline.
 */

#pragma once

#include <atomic>
#include <memory>
#include <optional>
#include <vector>

namespace antivirus {

/**
 * @class LockFreeQueue
 * @brief Multi-producer multi-consumer lock-free queue
 * 
 * Implementation based on bounded MPMC queue with atomic index tracking.
 * Uses cache-line padding to prevent false sharing.
 * 
 * @tparam T Element type (must be movable)
 */
template<typename T>
class LockFreeQueue {
public:
    /**
     * @brief Construct queue with given capacity
     * @param capacity Maximum number of elements (rounded to power of 2)
     */
    explicit LockFreeQueue(size_t capacity = 8192)
        : m_capacity(NextPowerOf2(capacity))
        , m_mask(m_capacity - 1)
        , m_buffer(m_capacity)
        , m_head(0)
        , m_tail(0)
    {
        for (size_t i = 0; i < m_capacity; ++i) {
            m_buffer[i].sequence.store(i, std::memory_order_relaxed);
        }
    }
    
    // Non-copyable, non-movable (due to atomics)
    LockFreeQueue(const LockFreeQueue&) = delete;
    LockFreeQueue& operator=(const LockFreeQueue&) = delete;
    LockFreeQueue(LockFreeQueue&&) = delete;
    LockFreeQueue& operator=(LockFreeQueue&&) = delete;
    
    /**
     * @brief Try to enqueue an element
     * @param value Value to enqueue
     * @return true if successful, false if queue is full
     */
    bool TryPush(T value) {
        Cell* cell;
        size_t pos = m_tail.load(std::memory_order_relaxed);
        
        for (;;) {
            cell = &m_buffer[pos & m_mask];
            size_t seq = cell->sequence.load(std::memory_order_acquire);
            intptr_t diff = static_cast<intptr_t>(seq) - static_cast<intptr_t>(pos);
            
            if (diff == 0) {
                // Slot is available
                if (m_tail.compare_exchange_weak(pos, pos + 1, std::memory_order_relaxed)) {
                    break;
                }
            } else if (diff < 0) {
                // Queue is full
                return false;
            } else {
                // Another thread got here first, try next
                pos = m_tail.load(std::memory_order_relaxed);
            }
        }
        
        cell->data = std::move(value);
        cell->sequence.store(pos + 1, std::memory_order_release);
        return true;
    }
    
    /**
     * @brief Try to dequeue an element
     * @return Element if available, nullopt if queue is empty
     */
    std::optional<T> TryPop() {
        Cell* cell;
        size_t pos = m_head.load(std::memory_order_relaxed);
        
        for (;;) {
            cell = &m_buffer[pos & m_mask];
            size_t seq = cell->sequence.load(std::memory_order_acquire);
            intptr_t diff = static_cast<intptr_t>(seq) - static_cast<intptr_t>(pos + 1);
            
            if (diff == 0) {
                // Data is available
                if (m_head.compare_exchange_weak(pos, pos + 1, std::memory_order_relaxed)) {
                    break;
                }
            } else if (diff < 0) {
                // Queue is empty
                return std::nullopt;
            } else {
                // Another thread got here first, try next
                pos = m_head.load(std::memory_order_relaxed);
            }
        }
        
        T data = std::move(cell->data);
        cell->sequence.store(pos + m_capacity, std::memory_order_release);
        return data;
    }
    
    /**
     * @brief Check if queue is empty (approximate)
     */
    [[nodiscard]] bool IsEmpty() const noexcept {
        return m_head.load(std::memory_order_relaxed) >= 
               m_tail.load(std::memory_order_relaxed);
    }
    
    /**
     * @brief Get approximate size
     */
    [[nodiscard]] size_t Size() const noexcept {
        size_t tail = m_tail.load(std::memory_order_relaxed);
        size_t head = m_head.load(std::memory_order_relaxed);
        return tail >= head ? tail - head : 0;
    }
    
    /**
     * @brief Get queue capacity
     */
    [[nodiscard]] size_t Capacity() const noexcept {
        return m_capacity;
    }

private:
    static constexpr size_t CACHE_LINE_SIZE = 64;
    
    struct alignas(CACHE_LINE_SIZE) Cell {
        std::atomic<size_t> sequence;
        T data;
    };
    
    [[nodiscard]] static size_t NextPowerOf2(size_t n) noexcept {
        n--;
        n |= n >> 1;
        n |= n >> 2;
        n |= n >> 4;
        n |= n >> 8;
        n |= n >> 16;
        n |= n >> 32;
        return n + 1;
    }
    
    const size_t m_capacity;
    const size_t m_mask;
    std::vector<Cell> m_buffer;
    
    // Separate cache lines for head and tail to prevent false sharing
    alignas(CACHE_LINE_SIZE) std::atomic<size_t> m_head;
    alignas(CACHE_LINE_SIZE) std::atomic<size_t> m_tail;
};

}  // namespace antivirus
