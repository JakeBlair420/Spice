#include <mach/mach.h>

kern_return_t set_generator(const char *new_generator);
const char *get_generator(void);
kern_return_t patch_nvram(void);
