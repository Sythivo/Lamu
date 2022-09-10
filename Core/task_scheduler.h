#pragma once

#include <memory>
#include <vector>
#include <thread>

// Mock TaskScheduler to Roblox

struct TaskScheduler {
	public:
		TaskScheduler() : alive(true) {}
		virtual ~TaskScheduler() = default;

		template <class Handle, class... Args>
		void queue(Handle handle, Args... args) {
			if (alive) {
				threads.push_back(std::move(std::thread(handle, args...)));
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