// Forked from https://github.com/Roblox/luau/blob/master/CLI/FileUtils.h

#pragma once

#include <optional>
#include <string>
#include <functional>
#include <vector>
#include <filesystem>
#include <fstream>

namespace FileSystem {
	std::optional<std::string> readFile(const std::string& name);
	bool isDirectory(const std::string& path);
	std::vector<std::filesystem::path> GetFilesInDirectory(std::string path);
}