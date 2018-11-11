#include "common.h"

#ifndef STAGE1_H
#define STAGE1_H

#define STAGE2_FD 6
void generate_stage1_rop_chain(offset_struct_t * offsets);
void stage1(int fd, offset_struct_t * offsets);

#endif
