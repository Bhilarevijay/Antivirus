/**
 * @file ThreadPool.cpp
 * @brief Work-stealing thread pool implementation
 */

#include "antivirus/threading/ThreadPool.hpp"

#ifdef _WIN32
    #include <Windows.h>
#endif

namespace antivirus {

ThreadPool::ThreadPool(size_t threadCount, bool enableNuma)
    : m_enableNuma(enableNuma)
    , m_globalQueue(16384)
{
    // Auto-detect thread count
    if (threadCount == 0) {
        threadCount = std::thread::hardware_concurrency();
        if (threadCount == 0) {
            threadCount = 4;  // Fallback
        }
    }
    
    m_threadCount = threadCount;
    
    // Create per-thread work-stealing queues
    m_localQueues.reserve(threadCount);
    for (size_t i = 0; i < threadCount; ++i) {
        m_localQueues.push_back(
            std::make_unique<WorkStealingQueue<TaskWrapper>>()
        );
    }
    
    // Start worker threads
    m_workers.reserve(threadCount);
    for (size_t i = 0; i < threadCount; ++i) {
        m_workers.emplace_back(&ThreadPool::WorkerLoop, this, i);
    }
}

ThreadPool::~ThreadPool() {
    Stop(false);
}

void ThreadPool::Submit(Task task) {
    if (!m_running.load()) {
        return;
    }
    
    TaskWrapper wrapper{std::move(task)};
    
    // Try to push to global queue
    while (!m_globalQueue.TryPush(std::move(wrapper))) {
        // Queue is full, yield and retry
        std::this_thread::yield();
        
        if (!m_running.load()) {
            return;
        }
    }
    
    m_pendingTasks.fetch_add(1);
    
    // Wake up a worker
    {
        std::lock_guard<std::mutex> lock(m_taskMutex);
        m_taskCondition.notify_one();
    }
}

size_t ThreadPool::GetThreadCount() const noexcept {
    return m_threadCount;
}

size_t ThreadPool::GetPendingTaskCount() const noexcept {
    return m_pendingTasks.load();
}

void ThreadPool::WaitAll() {
    std::unique_lock<std::mutex> lock(m_waitMutex);
    m_waitCondition.wait(lock, [this]() {
        return m_pendingTasks.load() == 0 && m_activeTasks.load() == 0;
    });
}

void ThreadPool::Stop(bool waitForTasks) {
    if (m_stopped.exchange(true)) {
        return;  // Already stopped
    }
    
    if (waitForTasks) {
        WaitAll();
    }
    
    m_running.store(false);
    
    // Wake up all workers
    {
        std::lock_guard<std::mutex> lock(m_taskMutex);
        m_taskCondition.notify_all();
    }
    
    // Join all worker threads
    for (auto& worker : m_workers) {
        if (worker.joinable()) {
            worker.join();
        }
    }
    
    m_workers.clear();
}

bool ThreadPool::IsRunning() const noexcept {
    return m_running.load();
}

void ThreadPool::WorkerLoop(size_t workerId) {
    // Set thread affinity for NUMA awareness
    if (m_enableNuma) {
        SetThreadAffinity(workerId);
    }
    
    while (m_running.load()) {
        if (!TryExecuteTask(workerId)) {
            // No task found, wait for notification
            std::unique_lock<std::mutex> lock(m_taskMutex);
            m_taskCondition.wait_for(lock, std::chrono::milliseconds(10), [this]() {
                return !m_running.load() || m_pendingTasks.load() > 0;
            });
        }
    }
}

bool ThreadPool::TryExecuteTask(size_t workerId) {
    Task task;
    
    // Try local queue first
    auto localTask = m_localQueues[workerId]->TryPop();
    if (localTask) {
        task = std::move((*localTask)->task);
        delete *localTask;
    }
    
    // Try global queue
    if (!task) {
        auto globalTask = m_globalQueue.TryPop();
        if (globalTask) {
            task = std::move(globalTask->task);
        }
    }
    
    // Try stealing from other workers
    if (!task && !TryStealTask(workerId, task)) {
        return false;
    }
    
    if (!task) {
        return false;
    }
    
    // Execute the task
    m_activeTasks.fetch_add(1);
    m_pendingTasks.fetch_sub(1);
    
    try {
        task();
    } catch (...) {
        // Swallow exceptions - caller should handle via future
    }
    
    m_activeTasks.fetch_sub(1);
    
    // Notify waiters if all tasks done
    if (m_pendingTasks.load() == 0 && m_activeTasks.load() == 0) {
        std::lock_guard<std::mutex> lock(m_waitMutex);
        m_waitCondition.notify_all();
    }
    
    return true;
}

bool ThreadPool::TryStealTask(size_t workerId, Task& task) {
    size_t numQueues = m_localQueues.size();
    
    // Random starting point to avoid contention
    static thread_local std::mt19937 rng(
        std::hash<std::thread::id>{}(std::this_thread::get_id())
    );
    size_t start = rng() % numQueues;
    
    for (size_t i = 0; i < numQueues; ++i) {
        size_t victim = (start + i) % numQueues;
        if (victim == workerId) {
            continue;
        }
        
        auto stolen = m_localQueues[victim]->TrySteal();
        if (stolen) {
            task = std::move((*stolen)->task);
            delete *stolen;
            return true;
        }
    }
    
    return false;
}

void ThreadPool::SetThreadAffinity(size_t workerId) {
#ifdef _WIN32
    // Set thread affinity to specific core
    DWORD_PTR mask = 1ULL << (workerId % 64);
    SetThreadAffinityMask(GetCurrentThread(), mask);
    
    // Set thread priority
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_NORMAL);
#else
    // TODO: Linux CPU affinity with sched_setaffinity
    (void)workerId;
#endif
}

std::shared_ptr<ThreadPool> CreateOptimalThreadPool() {
    return std::make_shared<ThreadPool>(0, true);
}

}  // namespace antivirus
