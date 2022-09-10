// Forked from https://github.com/Roblox/luau/blob/master/CLI/FileUtils.h

#pragma once

#include <optional>
#include <string>
#include <functional>
#include <vector>

namespace FileSystem {
	std::optional<std::string> readFile(const std::string& name);
}