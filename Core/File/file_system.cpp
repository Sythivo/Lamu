// Forked from https://github.com/Roblox/luau/blob/master/CLI/FileUtils.cpp

#include "file_system.h"

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#else
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#endif

#include <string.h>

#include "../../Luau/Common/Common.h"

#ifdef _WIN32
static std::wstring fromUtf8(const std::string& path)
{
    size_t result = MultiByteToWideChar(CP_UTF8, 0, path.data(), int(path.size()), nullptr, 0);
    LUAU_ASSERT(result);

    std::wstring buf(result, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, path.data(), int(path.size()), &buf[0], int(buf.size()));

    return buf;
}

static std::string toUtf8(const std::wstring& path)
{
    size_t result = WideCharToMultiByte(CP_UTF8, 0, path.data(), int(path.size()), nullptr, 0, nullptr, nullptr);
    LUAU_ASSERT(result);

    std::string buf(result, '\0');
    WideCharToMultiByte(CP_UTF8, 0, path.data(), int(path.size()), &buf[0], int(buf.size()), nullptr, nullptr);

    return buf;
}
#endif

namespace FileSystem {
    std::optional<std::string> readFile(const std::string& path)
    {
#ifdef _WIN32
        FILE* file = _wfopen(fromUtf8(path).c_str(), L"rb");
#else
        FILE* file = fopen(path.c_str(), "rb");
#endif

        if (!file)
            return std::nullopt;

        fseek(file, 0, SEEK_END);
        long length = ftell(file);
        if (length < 0)
        {
            fclose(file);
            return std::nullopt;
        }
        fseek(file, 0, SEEK_SET);

        std::string result(length, 0);

        size_t read = fread(result.data(), 1, length, file);
        fclose(file);

        if (read != size_t(length))
            return std::nullopt;

        // Skip first line if it's a shebang
        if (length > 2 && result[0] == '#' && result[1] == '!')
            result.erase(0, result.find('\n'));

        return result;
    }
    bool isDirectory(const std::string& path)
    {
        return std::filesystem::is_directory(path);
    }

    std::vector<std::filesystem::path> GetFilesInDirectory(std::string path)
    {
        std::vector<std::filesystem::path> files;
        for (std::filesystem::directory_entry const& dir_entry : std::filesystem::directory_iterator{ path })
            if (dir_entry.is_regular_file())
                files.push_back(std::filesystem::absolute(dir_entry.path()));
        return files;
    }
}