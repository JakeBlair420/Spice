#include <string.h>             // strcmp

#include <shared/common.h>
#include "common.h"
#include "install.h"
#include <shared/jailbreak.h>

// TODO: port generator.m here

// This is invoked in four different ways:
// - When the dylib is loaded into racoon.
//   This is the only case where we actually wanna go this route,
//   so we need to detect whether we're running inside racoon.
//   In that case we also won't return since we exec the trampoline.
// - When the trampoline is invoked for post-exploitation.
//   This is handled by main() via a "pwn" argument.
// - When the trampoline is invoked for installation.
//   This is handled by main() via an "install" argument.
// - When the trampoline is invoked for testing from macOS.
//   This is handled by ifdefs.
__attribute__((constructor)) static void dylib_main(void)
{
    // TODO: (NOTE: must all be done without imports!)
    // - find a way to tell whether we're running in racoon or not
    //   (executable path is probably wrong since we hijack some daemon)
    // - find mach port handle & struct somehow
    // - finish the exploit (platformize, root, unsandbox, proper tfp0)
    // - execve trampoline
}

int main(int argc, const char **argv)
{
#ifdef __x86_64__
    if(argc != 3)
    {
        LOG("Usage: %s racoon dyld_cache", argv[0]);
        return -1;
    }
#   warning TODO: 32bit
    return install("./racoon.conf", argv[1], argv[2]);
#else
    if(argc != 2)
    {
        LOG("Usage: %s install|pwn", argv[0]);
        return -1;
    }
    else if(strcmp(argv[1], "install") == 0)
    {
        return install("/etc/racoon/racoon.conf", "/usr/sbin/racoon",
#ifdef __LP64__
            "/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64"
#else
            "/System/Library/Caches/com.apple.dyld/dyld_shared_cache_armv7s"
#endif
        );
    }
    else if(strcmp(argv[1], "pwn") == 0)
    {
        return jailbreak(JBOPT_POST_ONLY);
    }
    LOG("Come again?");
    return -1;
#endif
}
