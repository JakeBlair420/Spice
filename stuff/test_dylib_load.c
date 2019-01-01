#include <stdio.h>
#include <dlfcn.h>


__attribute__((constructor))
int main() {
	printf("%d\n",dlopen("/usr/lib/racoon.dylib",RTLD_NOW));
}
