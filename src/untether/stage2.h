#include "common.h"
#ifndef STAGE2_H
#define STAGE2_H
uint64_t get_addr_from_name(offset_struct_t * offsets,char * name);
void stage2(offset_struct_t * offsets,char * base_dir); 
#endif
