#include "common.h"
#ifndef RACOON_WWW_H
#define RACOON_WWW_H

#define RACOON_YY_BUF_SIZE 16384
#define BYTES_PER_WRITE 400 // approx amount of bytes we need for one 64-bit write FIXME: this can be prob way lower than 400
#define shift_mask(value,shift,mask) ((value >> shift) & mask)
#define shiftm(value,shift) shift_mask(value,shift,0xff)

void trigger_exec(int fd,uint32_t padding, uint64_t address);
void www64(int fd,offset_struct_t * offsets, uint64_t where, uint64_t what);

#endif
