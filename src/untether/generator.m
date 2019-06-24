#include "install.h"

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
