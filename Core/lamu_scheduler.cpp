#include "lamu.h"

#include "../Luau/VM/lstate.h"
#include "../Luau/VM/lualib.h"

void lamu_resume(lua_State* L, lua_State* from, int narg) {
    Lamu::task_scheduler->queue(lua_resume, L, from, narg);
}

int lamu_spawn(lua_State* L) {
    lua_State* cL;
    int narg = (int)(L->top - L->base) - 1;

    if (lua_isfunction(L, 1)) {
        cL = lua_newthread(L);
        lua_xpush(L, cL, 1);
        narg++;
    }
    else if (lua_isthread(L, 1)) {
        cL = lua_tothread(L, 1);
    }
    else {
        luaL_error(L, ERR_THREAD_EXPECTATION);
        return 0;
    }

    lua_xmove(L, cL, narg);

    lamu_resume(cL, L, narg);

    return 0;
}

int lamu_wait(lua_State* L) {
    LamuThread::sleep(luaL_checknumber(L, 1) * 1000.0);
    return 0;
}

int lamu_delay(lua_State* L) {
    lua_State* cL;
    int narg = (int)(L->top - L->base) - 1;

    double duration = luaL_checknumber(L, 1);

    if (lua_isfunction(L, 2)) {
        cL = lua_newthread(L);
        lua_xpush(L, cL, 2);
        narg++;
    }
    else if (lua_isthread(L, 2)) {
        cL = lua_tothread(L, 2);
    }
    else {
        luaL_error(L, ERR_THREAD_EXPECTATION);
        return 0;
    }

    lua_xmove(L, cL, narg);

    Lamu::task_scheduler->queue([cL, L, narg, duration]() {
        LamuThread::sleep(duration);
        lua_resume(cL, L, narg);
    });

    return 0;
}

namespace Lamu {
    TaskScheduler* task_scheduler = new TaskScheduler;

    static const luaL_Reg task_functions[] = {
            {"spawn", lamu_spawn},
            {"defer", lamu_spawn}, // No task list for defer, support keyword for Roblox Developers
            {"wait", lamu_wait},
            {"delay", lamu_delay},
            {NULL, NULL},
    };
    int open_task(lua_State* L)
    {
        luaL_register(L, "task", task_functions);
        
        return 0;
    }
}