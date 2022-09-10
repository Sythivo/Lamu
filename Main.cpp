#include "Luau/Compiler/luacode.h"
#include <fstream>

#ifdef _WIN32

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#endif

#include <filesystem>
#include "Luau/VM/lua.h"
#include "Luau/VM/lualib.h"
#include "Luau/VM/lvm.h"
#include "Core/lamu.h"

int main(int args_count, char* args[])
{
    // TODO: command invoke based run command
    // 'lamu <path relative to invoke context>'
    // testing run 'root.luau' file
    std::string root_test_name = "root.luau";
    std::filesystem::path current = std::filesystem::current_path();;

    std::string source_input;

    std::ifstream source_file((current.parent_path() / root_test_name).string());
    if (source_file.is_open())
    {
        source_file.seekg(0, std::ios::end);
        source_input.reserve(source_file.tellg());
        source_file.seekg(0, std::ios::beg);

        source_input.assign(std::istreambuf_iterator<char>(source_file), std::istreambuf_iterator<char>());

        source_file.close();
    }
    else
        return EXIT_FAILURE;

    lua_State* L = luaL_newstate();

    const char* source = source_input.c_str();

    size_t bytecode_size = 0;
    char* bytecode = luau_compile(source, strlen(source), NULL, &bytecode_size);

    luaL_openlibs(L);
    Lamu::open(L);

    int result = luau_load(L, "root", bytecode, bytecode_size, 0);

    if (result == 0) {
        int presult = lua_pcall(L, 0, LUA_MULTRET, 0);
        if (presult != 0) {
            fprintf(stderr, "Failed to run script: %s\n", lua_tostring(L, -1));
        }

        // Main Thread, wait for Threads to finish
        Lamu::task_scheduler->finish();
    }
    else {
        fprintf(stderr, "Failed to run script: %s\n", lua_tostring(L, -1));
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}