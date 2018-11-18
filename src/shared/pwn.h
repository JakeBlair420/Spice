#ifndef PWN_H
#define PWN_H

#include <mach/mach.h>

#include "common.h"

kern_return_t pwn_kernel(offsets_t offsets, task_t *tfp0, kptr_t *kbase);

#endif
