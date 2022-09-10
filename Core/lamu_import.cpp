#include "lamu.h"
#include "File/file_system.h"

#include "../Luau/VM/lvm.h"
#include "../Luau/VM/lualib.h"
#include "../Luau/Compiler/luacode.h"
#include "../Luau/Compiler/Compiler.h"

#include <unordered_map>

namespace Lamu {
    int open_import(lua_State* L)
    {
        // forked from https://github.com/Roblox/luau/blob/master/CLI/Repl.cpp
        lua_pushcfunction(L, 
            [](lua_State* L) {
                std::string name = luaL_checkstring(L, 1);
                std::string chunkname = "=" + name;

                luaL_findtable(L, LUA_REGISTRYINDEX, "_MODULES", 1);

                lua_getfield(L, -1, name.c_str());
                if (!lua_isnil(L, -1))
                {
                    if (lua_isstring(L, -1))
                        lua_error(L);

                    return 1;
                }

                lua_pop(L, 1);

                std::optional<std::string> source = FileSystem::readFile(name + ".luau");
                if (!source)
                {
                    source = FileSystem::readFile(name + ".lua"); // try .lua if .luau doesn't exist
                    if (!source)
                        luaL_argerrorL(L, 1, ("error loading " + name).c_str()); // if neither .luau nor .lua exist, we have an error
                }

                // module needs to run in a new thread, isolated from the rest
                // note: we create ML on main thread so that it doesn't inherit environment of L
                lua_State* GL = lua_mainthread(L);
                lua_State* ML = lua_newthread(GL);
                lua_xmove(GL, L, 1);
                // new thread needs to have the globals sandboxed
                luaL_sandboxthread(ML);

                Luau::CompileOptions result = {};
                result.optimizationLevel = 1;
                result.coverageLevel = 0;
                result.debugLevel = 1;

                // now we can compile & run module on the new thread
                std::string bytecode = Luau::compile(*source, result);
                if (luau_load(ML, chunkname.c_str(), bytecode.data(), bytecode.size(), 0) == 0)
                {
                    int status = lua_resume(ML, L, 0);

                    if (status == 0)
                        if (lua_gettop(ML) != 1)
                            lua_pushstring(ML, "module must return a single value");
                    else if (status == LUA_YIELD) // thread yield;
                        lua_pushstring(ML, "module can not yield");
                    else if (!lua_isstring(ML, -1))
                        lua_pushstring(ML, "unknown error while running module");
                }

                // there's now a return value on top of ML; L stack: _MODULES ML
                lua_xmove(ML, L, 1);
                lua_pushvalue(L, -1);
                lua_setfield(L, -4, name.c_str());

                // L stack: _MODULES ML result
                if (lua_isstring(L, -1))
                    lua_error(L);

                return 1;
            }, 
            "import"
        );
        lua_setglobal(L, "import");

        return 1;
    }
}