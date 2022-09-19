#include "Luau/Compiler/luacode.h"
#include <fstream>

#ifndef _WIN32
#include <cstring>
#endif

#include "Core/File/file_system.h"
#include "Luau/VM/lua.h"
#include "Luau/VM/lualib.h"
#include "Luau/VM/lvm.h"
#include "Core/lamu.h"

int main(int args_count, char* args[])
{
    std::string source_path;

#ifdef _RELEASE

    if (args_count > 1) 
    {
        source_path = args[1];
    }
    else 
    {
        fprintf(stderr, "Error: No Luau/Lua File Input");
        return EXIT_FAILURE;
    }

#else

    source_path = "./root.luau";

#endif

    if (FileSystem::isDirectory("./.modules")) {
        std::vector<std::filesystem::path> files = FileSystem::GetFilesInDirectory("./.modules");

        for (std::filesystem::path file : files) {
            Modules.push_back(LoadModule(file.stem().string().c_str(), file.string()));
        }
    };

    std::optional<std::string> source_input = FileSystem::readFile(source_path);

    if (!source_input.has_value())
    {
        fprintf(stderr, "Error: File not found");
        return EXIT_FAILURE;
    }

    lua_State* L = luaL_newstate();

    const char* source = source_input.value().c_str();

    size_t bytecode_size = 0;
    char* bytecode = luau_compile(source, strlen(source), NULL, &bytecode_size);

    luaL_openlibs(L);
    Lamu::open(L);

    for (Module module : Modules) {
        OnLoaded OnLoadFunction = GetModuleFunction<OnLoaded>(module, "OnLoaded");
        if (OnLoadFunction != NULL)
            OnLoadFunction(L);
    }

    int result = luau_load(L, "root", bytecode, bytecode_size, 0);

    if (result == 0) {
        int presult = lua_pcall(L, 0, LUA_MULTRET, 0);
        if (presult != 0) {
            fprintf(stderr, "Failed to run script: %s\n", lua_tostring(L, -1));
        }

        // Main Thread, wait for Threads to finish
        Lamu::task_scheduler->finish();

        for (Module module : Modules)
            LFreeModule(module);
    }
    else {
        fprintf(stderr, "Failed to run script: %s\n", lua_tostring(L, -1));
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}