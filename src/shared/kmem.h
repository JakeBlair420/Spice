
#include <mach/mach.h>

void kread(uint64_t kaddr, void* buffer, uint32_t length);
void kwrite(uint64_t kaddr, void* buffer, uint32_t length);

uint32_t rk32(uint64_t kaddr);
uint64_t rk64(uint64_t kaddr);

void wk32(uint64_t kaddr, uint32_t val);
void wk64(uint64_t kaddr, uint64_t val);

uint64_t kalloc(uint64_t size);
void kfree(uint64_t addr, uint64_t size);
void kprotect(uint64_t kaddr, uint32_t size, int prot);
