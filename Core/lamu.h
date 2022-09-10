#pragma once

#include "../Luau/VM/lua.h"
#include "task_scheduler.h"

#include <functional>
#include <vector>

#define ERR_INVALID_METHOD_CALL "Expected ':' not '.'\n"
#define ERR_THREAD_EXPECTATION "Expected 'function' or 'thread'"

namespace LamuThread {
	void sleep(double milliseconds);
}

namespace Lamu {
	// TODO: Make task_scheduler more expandable
	extern TaskScheduler* task_scheduler;

	int open_import(lua_State* L);
	int open_http(lua_State* L);
	int open_base(lua_State* L);
	int open_task(lua_State* L);
	int open(lua_State* L);
}