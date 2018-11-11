#ifndef ROP_H
#define ROP_H
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


#endif
