#ifndef KDATA_H
#define KDATA_H

#include <stddef.h>             // size_t
#include <mach/mach.h>

#include "common.h"

#define KDATA_SIZE 0x400

kptr_t kdata_init(void);
kern_return_t kdata_write(const void *data);
kern_return_t kdata_read(void *buffer);
void kdata_cleanup(void);

#endif
