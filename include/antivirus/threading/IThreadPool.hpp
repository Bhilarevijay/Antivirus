/**
 * @file IThreadPool.hpp
 * @brief Abstract interface for thread pool
 */

#pragma once

#include <functional>
#include <future>
#include <memory>

namespace antivirus {

/**
 * @interface IThreadPool
 * @brief Thread pool interface for task execution
 */
class IThreadPool {
public:
    using Task = std::function<void()>;
    
    virtual ~IThreadPool() = default;
    
    /**
     * @brief Submit a task for execution
     * @param task Task to execute
     */
    virtual void Submit(Task task) = 0;
    
    /**
     * @brief Submit a task and get a future for the result
     * @param task Callable returning a result
     * @return Future for the result
     */
    template<typename F, typename R = std::invoke_result_t<F>>
    [[nodiscard]] std::future<R> SubmitWithResult(F&& task) {
        auto promise = std::make_shared<std::promise<R>>();
        auto future = promise->get_future();
        
        Submit([promise, task = std::forward<F>(task)]() mutable {
            try {
                if constexpr (std::is_void_v<R>) {
                    task();
                    promise->set_value();
                } else {
                    promise->set_value(task());
                }
            } catch (...) {
                promise->set_exception(std::current_exception());
            }
        });
        
        return future;
    }
    
    /**
     * @brief Get number of worker threads
     */
    [[nodiscard]] virtual size_t GetThreadCount() const noexcept = 0;
    
    /**
     * @brief Get number of pending tasks
     */
    [[nodiscard]] virtual size_t GetPendingTaskCount() const noexcept = 0;
    
    /**
     * @brief Wait for all tasks to complete
     */
    virtual void WaitAll() = 0;
    
    /**
     * @brief Stop the thread pool
     * @param waitForTasks If true, wait for pending tasks to complete
     */
    virtual void Stop(bool waitForTasks = true) = 0;
    
    /**
     * @brief Check if the pool is running
     */
    [[nodiscard]] virtual bool IsRunning() const noexcept = 0;

protected:
    IThreadPool() = default;
};

using IThreadPoolPtr = std::shared_ptr<IThreadPool>;

}  // namespace antivirus
