#include "lamu.h"

#include "../Luau/VM/lualib.h"

#include <chrono>
#include <cmath>

namespace LamuThread {
    void sleep(double seconds)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds((int)std::round(seconds * 1000.0)));
    }
}

namespace Lamu {
    int open_base(lua_State* L)
    {
        //Load Lamu Global Values

        lua_getglobal(L, "_G");
        lua_pushcfunction(L,
            [](lua_State* L) {
                LamuThread::sleep(luaL_checknumber(L, 1));
                return 0;
            }, "wait"
        );
        lua_setfield(L, -2, "wait");

        return 0;
    }

    int open(lua_State* L)
    {
        open_base(L);
        open_http(L);
        open_task(L);

        open_import(L);

        return 0;
    }
}