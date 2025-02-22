#pragma once
#include <queue>
#include <mutex>
#include <condition_variable>

template <typename T>
class SafeQueue {
private:
    std::queue<T> q;
    std::mutex m;
    std::condition_variable cv;

public:
    void push(T value) {
        std::lock_guard<std::mutex> lock(m);
        q.push(value);
        cv.notify_one();
    }

    T pop() {
        std::unique_lock<std::mutex> lock(m);
        cv.wait(lock, [&]{ return !q.empty(); });
        T value = q.front();
        q.pop();
        return value;
    }
};