#include <unistd.h>
#include "rop.h"

#ifndef COMMON_H
#define COMMON_H

struct offset_struct {
	int dns4_array_to_lcconf;
	rop_gadget_t * stage1_ropchain;
	uint32_t str_buff_offset;
	uint32_t max_slide;
	uint32_t slide_value;
	uint64_t pivot_x21;
	uint64_t memmove;
	uint64_t lcconf_counter_offset;
	uint64_t BEAST_GADGET;
	uint64_t longjmp;
	uint64_t open;
	uint64_t mmap;
	uint64_t stage2_base;
	uint64_t stage2_size;
};
typedef struct offset_struct offset_struct_t;

#endif
