#include "common.h"
#include "img.h" // libjake
#ifndef ULAND_OFFSETFINDER_H
#define ULAND_OFFSETFINDER_H
// finds the rop gadgets inside of the cache and the other addresses inside of racoon
// if you want to know how the gadgets look either check rop.h, stage1.c or uland_offsetfinder.m
jake_img_t racoon_img;
jake_img_t cache_img;

// helper funcs
// find raw binary data that might be aligned inside of the binary
void * find_data_raw(const void * bin, size_t bin_size, void * data, size_t data_size,int search_aligned);
// find a string inside of the binary
void * find_str(char * str);
// find an xref to a specific address inside of the binary (basically code accessing data)
void * find_ref(void * addr);
// find code xrefing a specific address (so basically code calling other code)
void * find_code_xref(void * addr);

// racoon
// find the address of the isakmp_cfg_config struct in racoon globals
void * isakmp_cfg_config_addr();
// find the address of the lcconf ptr inside of racoons globals
void * lcconf_addr();

// cache
// find the maximum cache slide by parsing the cache header
size_t get_cache_maxslide();
// find the lazy memmove ptr we want to target for our overwrite inside of the cache data section
void * memmove_cache_ptr(const char * path);
// find the address to perform a stack pivot inside of the cache
void * get_stackpivot_addr(const char * path);
// find the address of the cbz x0 gadget used to misalign the stack for rop loops
void * get_cbz_x0_gadget();
// find the address this gadget loads the code pointer from we want to overwrite
void * get_cbz_x0_x16_load(void * cbz_x0_gadget_addr);
// get the address that gets used by errno so that we can mmap it and don't crash when a syscall returns an error
void * get_errno_offset(const char * path);
// get the address of the gadget we use to pivot the stack (this will be the first code we run before getting into the stage 1 rop chain)
void * get_pivot_x21_gadget();
// find the beast gadget that's perfect for roping
void * get_beast_gadget();
// find the gadget to store x0 at a known address in mem
void * get_str_x0_gadget();
// find the gadget to add two vars and store the result in x0
void * get_add_x0_gadget();

// more control functions
void init_uland_offsetfinder(const char * racoon_bin, const char * cache);
#define find_data(bin,bin_size,data,data_size) find_data_raw(bin,bin_size,data,data_size,1)

// convert between the address and the fileoffset for the cache
#define CACHE_FILE2ADDR(addr) ((void*)jake_vaddr_to_fileoff(cache_img,(uint64_t)addr)+0x180000000)
#define CACHE_ADDR2FILE(addr) ((void*)jake_fileoff_to_vaddr(cache_img,(uint64_t)addr-0x180000000))

#endif
