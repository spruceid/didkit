#include <dlfcn.h>
#include <err.h>
#include <stdio.h>
#include "didkit.h"

int main() {
	void *lib = dlopen("../target/release/libdidkit.so", RTLD_NOW);
	if (lib == NULL) errx(1, "dlopen: %s", dlerror());
	const char *(*didkit_get_version)() = dlsym(lib, "didkit_get_version");
	if (didkit_get_version == NULL) errx(1, "unable to find version function");
	const char *version = didkit_get_version();
	printf("C libdidkit version: %s\n", version);
	int rc = dlclose(lib);
	if (rc < 0) errx(1, "dlclose: %s", dlerror());
}
