#include <mach/mach.h>

kern_return_t set_generator(const char *new_generator);
const char *get_generator(void);
kern_return_t unlock_nvram(void);
kern_return_t lock_nvram(void);
