#include <unistd.h>
#include "rop.h"

#import <Foundation/Foundation.h>

#ifndef COMMON_H
#define COMMON_H

#ifdef RELEASE
#   define LOG(str, args...) do { } while(0)
#else
#   define LOG(str, args...) do { NSLog(@ str "\n", ##args); } while(0)
#endif

struct offset_struct {
	int dns4_array_to_lcconf;
	rop_gadget_t * stage1_ropchain;
	rop_gadget_t * stage3_ropchain;
	uint32_t str_buff_offset;
	uint32_t max_slide;
	uint32_t slide_value;
	uint64_t pivot_x21;
	uint64_t memmove;
	uint64_t lcconf_counter_offset;
	uint64_t BEAST_GADGET;
	uint64_t BEAST_GADGET_LOADER;
	uint64_t str_x0_gadget;
	uint64_t str_x0_gadget_offset;
	uint64_t longjmp;
	uint64_t open;
	uint64_t mmap;
	uint64_t memcpy;
	uint64_t stage2_base;
	uint64_t stage2_size;
	uint64_t stage3_base;
	uint64_t stage3_size;
	void * stage3_databuffer;
	uint64_t stage3_databuffer_len;
};
typedef struct offset_struct offset_struct_t;

#endif
