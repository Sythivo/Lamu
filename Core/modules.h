#pragma once

#if _WIN32
#include <windows.h>
#include <libloaderapi.h>
#else
#include <dlfcn.h>
#endif

#include <string>
#include <iostream>

struct Module
{
	const char* name;
#if _WIN32
	HINSTANCE id;
#else
	void* id;
#endif
};

template<typename T>
T GetModuleFunction(Module module, const char* func_name) {
#if _WIN32
	return (T)GetProcAddress(module.id, func_name);
#else
	return (T)dlsym(module.id, func_name.c_str());
#endif
}

extern Module LoadModule(const char* name, std::string path);
extern void LFreeModule(Module module);