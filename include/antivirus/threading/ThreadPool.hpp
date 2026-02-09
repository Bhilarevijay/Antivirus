/**
 * @file ThreadPool.hpp
 * @brief Work-stealing thread pool implementation
 * 
 * High-performance thread pool with work stealing for optimal
 * load balancing across CPU cores.
 */

#pragma once

#include "antivirus/threading/IThreadPool.hpp"
#include "antivirus/threading/WorkStealingQueue.hpp"
#include "antivirus/utils/LockFreeQueue.hpp"

#include <thread>
#include <vector>
#include <random>
#include <condition_variable>

#ifdef _WIN32
    #include <Windows.h>
#endif

namespace antivirus {

/**
 * @class ThreadPool
 * @brief Production work-stealing thread pool
 * 
 * Features:
 * - Work-stealing for load balancing
 * - NUMA-aware thread affinity (Windows)
 * - Dynamic task submission
 * - Graceful shutdown
 */
class ThreadPool final : public IThreadPool {
public:
    /**
     * @brief Create thread pool with specified thread count
     * @param threadCount Number of worker threads (0 = auto-detect)
     * @param enableNuma Enable NUMA-aware thread affinity
     */
    explicit ThreadPool(size_t threadCount = 0, bool enableNuma = true);
    
    ~ThreadPool() override;
    
    // Non-copyable
    ThreadPool(const ThreadPool&) = delete;
    ThreadPool& operator=(const ThreadPool&) = delete;
    
    void Submit(Task task) override;
    [[nodiscard]] size_t GetThreadCount() const noexcept override;
    [[nodiscard]] size_t GetPendingTaskCount() const noexcept override;
    void WaitAll() override;
    void Stop(bool waitForTasks = true) override;
    [[nodiscard]] bool IsRunning() const noexcept override;

private:
    struct TaskWrapper {
        Task task;
    };
    
    void WorkerLoop(size_t workerId);
    bool TryExecuteTask(size_t workerId);
    bool TryStealTask(size_t workerId, Task& task);
    void SetThreadAffinity(size_t workerId);
    
    size_t m_threadCount;
    bool m_enableNuma;
    
    std::vector<std::thread> m_workers;
    std::vector<std::unique_ptr<WorkStealingQueue<TaskWrapper>>> m_localQueues;
    LockFreeQueue<TaskWrapper> m_globalQueue;
    
    std::atomic<bool> m_running{true};
    std::atomic<bool> m_stopped{false};
    std::atomic<size_t> m_pendingTasks{0};
    std::atomic<size_t> m_activeTasks{0};
    
    std::mutex m_waitMutex;
    std::condition_variable m_waitCondition;
    std::condition_variable m_taskCondition;
    std::mutex m_taskMutex;
};

/**
 * @brief Create thread pool with optimal settings for current hardware
 */
[[nodiscard]] std::shared_ptr<ThreadPool> CreateOptimalThreadPool();

}  // namespace antivirus
