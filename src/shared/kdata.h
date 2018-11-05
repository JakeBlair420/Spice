#ifndef KDATA_H
#define KDATA_H

#include <stddef.h>             // size_t
#include <mach/mach.h>

#include "common.h"

kptr_t kdata_init(void);
kern_return_t kdata_write(const void *data, size_t len);
void kdata_cleanup(void);

#endif
