#pragma once

#include <memory>
#include <vector>
#include <thread>
#include <future>

// Mock TaskScheduler to Roblox

struct TaskScheduler {
	public:
		TaskScheduler() : alive(true) {}
		virtual ~TaskScheduler() = default;

		template <class Handle, class... Args>
		void queue(Handle handle, Args... args) {
			if (alive) {
				std::lock_guard<std::mutex> lock(mutex);
				threads.emplace_back(std::thread([handle, args..., this]() {
					handle(args...);
					std::async(&TaskScheduler::clean, this, std::this_thread::get_id());
				}));
			}
		}

		void clean(std::thread::id id) {
			std::lock_guard<std::mutex> lock(mutex);
			std::vector<std::thread>::iterator fthread = std::find_if(threads.begin(), threads.end(), [id](std::thread& t){ 
				return (t.get_id() == id); 
			});
			if (fthread != threads.end())
			{
				fthread->detach();
				threads.erase(fthread);
			}		
		}

		int count() {
			return threads.size();
		}

		void finish() {
			alive = false;

			for (std::thread& thread : threads)
				if (thread.joinable())
					thread.join();
		}
	private:
		std::vector<std::thread> threads;
		std::mutex mutex;
		bool alive;
};