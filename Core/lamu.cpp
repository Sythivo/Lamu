#include "lamu.h"

#include "../Luau/VM/lualib.h"

std::vector<Module> Modules;

namespace Lamu {
    int open_base(lua_State* L)
    {
        //Load Lamu Global Values

        lua_getglobal(L, "_G");
        lua_pushcfunction(L,
            [](lua_State* L) {
                double seconds = luaL_checknumber(L, 1);
                double elaspsedtime = 0;

                std::chrono::high_resolution_clock::time_point start = std::chrono::high_resolution_clock::now();

                thread::sleep(seconds);

                std::chrono::high_resolution_clock::time_point end = std::chrono::high_resolution_clock::now();

                auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start);
                elaspsedtime = elapsed.count() / (double)TIME_NANO;

                lua_pushnumber(L, elaspsedtime);
                lua_pushnumber(L, std::floor((elaspsedtime - seconds) * TIME_NANO) / TIME_NANO);
                return 2;
            }, "wait"
        );
        lua_setfield(L, -2, "wait");

        return 0;
    }

    int open(lua_State* L)
    {
        open_base(L);
        open_task(L);

        open_import(L);

        return 0;
    }
}