#include "common.h"

#ifndef STAGE1_H
#define STAGE1_H

#define DYLD_CACHE_FD 6
#define STAGE2_FD (DYLD_CACHE_FD+1)
void generate_stage1_rop_chain(offset_struct_t * offsets);
void stage1(int fd, offset_struct_t * offsets);

#endif
