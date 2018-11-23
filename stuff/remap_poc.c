#include <fcntl.h>
#include <stdio.h>
#include <sys/mman.h>

#ifdef __x86_64__
#   define CACHE_FILE "/var/db/dyld/dyld_shared_cache_x86_64h"
#   define REMAP_ADDR 0x110000000
#   define REMAP_SIZE 0x2fe4a000    /* __TEXT segment only */
#   define JUMP_ADDR  0x2fc246f0    /* cache offset of write() */
#   define END_ADDR   0x2fc2211c    /* cache offset of __exit() */
#elif defined(__arm64__)
#   define CACHE_FILE "/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64"
#   define REMAP_ADDR 0x101000000
#   define REMAP_SIZE 0x1e8a0000    /* __TEXT segment only */
#   define JUMP_ADDR  0x624c9c      /* cache offset of write() */
#   define END_ADDR   0x6268e0      /* cache offset of __exit() */
#else
#   error fuck is a blob
#endif

extern void goodbye(int fd, void *buf, size_t len, unsigned long long fn, unsigned long long x30) __attribute__((noreturn));

__asm__
(
    "_goodbye:\n"
#ifdef __x86_64__
    "mov %r8, 0(%rsp)\n"
    "jmp *%rcx\n"
#else
    "mov x30, x4\n"
    "br x3\n"
#endif
);

int main(void)
{
    int fd = open(CACHE_FILE, O_RDONLY);
    printf("fd: %i\n", fd);

    void *p = mmap((void*)REMAP_ADDR, REMAP_SIZE, PROT_READ | PROT_EXEC, MAP_FILE | MAP_SHARED, fd, 0);
    printf("mmap: %p\n", p);

    // Jump somewhere
    goodbye(1, "le test\n", 8, REMAP_ADDR + JUMP_ADDR, REMAP_ADDR + END_ADDR);

    return 0;
}
