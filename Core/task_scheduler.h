#pragma once

#include <memory>
#include <vector>
#include <thread>

// Mock TaskScheduler to Roblox

// TODO: Work on a thread pool
#ifndef LAMU_MAX_THREADS
#define LAMU_MAX_THREADS std::max(1u, std::thread::hardware_concurrency() > 0 ? std::thread::hardware_concurrency() - 1 : 0);
#endif

struct TaskScheduler {
	public:
		TaskScheduler() : alive(true) {}
		virtual ~TaskScheduler() = default;

		template <class Handle, class... Args>
		void queue(Handle handle, Args... args) {
			if (alive) {
				threads.emplace_back(std::thread(handle, args...));
			}
		}

		void finish() {
			alive = false;

			for (std::thread& thread : threads)
				if (thread.joinable())
					thread.join();
		}
	private:
		std::vector<std::thread> threads;

		bool alive;
};