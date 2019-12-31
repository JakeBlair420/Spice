#include "install.h"


// start of exeuction flow for the generator of the config file
// this was planed to be ported into main.m but I never did :|
int main(int argc, const char **argv)
{
        return install("/etc/racoon/racoon.conf", "/usr/sbin/racoon",
#ifdef __LP64__
            "/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64"
#else
            "/System/Library/Caches/com.apple.dyld/dyld_shared_cache_armv7s"
#endif
		);
}
