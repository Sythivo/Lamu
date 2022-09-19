#include "modules.h"

Module LoadModule(const char* name, std::string path) {
#if _WIN32
	HINSTANCE module_id = LoadLibrary(path.c_str());
#else
	void* module_id = dlopen(path.c_str(), RTLD_LAZY);
#endif

	if (module_id == NULL) {
		std::cout << "cannot locate the .dll file" << std::endl;
		return { name, NULL };
	}
	std::cout << "Loaded " << name << std::endl;
	return { name , module_id };
}

void LFreeModule(Module module) {
#if _WIN32
	FreeLibrary(module.id);
#else
	dlclose(module.id);
#endif
};