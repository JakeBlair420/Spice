#include "common.h"
#include "img.h" // libjake
#ifndef ULAND_OFFSETFINDER_H
#define ULAND_OFFSETFINDER_H
jake_img_t racoon_img;
jake_img_t cache_img;

void * find_data_raw(const void * bin, size_t bin_size, void * data, size_t data_size,int search_aligned);
void * find_str(char * str);
void * find_ref(void * addr);
void * find_code_xref(void * addr);
void * isakmp_cfg_config_addr();
void * lcconf_addr();
size_t get_cache_maxslide();
void * memmove_cache_ptr(const char * path);
void * get_stackpivot_addr(const char * path);
void * get_cbz_x0_gadget();
void * get_cbz_x0_x16_load(void * cbz_x0_gadget_addr);
void * get_errno_offset(const char * path);
void * get_pivot_x21_gadget();
void * get_beast_gadget();
void * get_str_x0_gadget();
void * get_add_x0_gadget();
void init_uland_offsetfinder(const char * racoon_bin, const char * cache);
#define find_data(bin,bin_size,data,data_size) find_data_raw(bin,bin_size,data,data_size,1)

#define CACHE_FILE2ADDR(addr) ((void*)jake_vaddr_to_fileoff(cache_img,(uint64_t)addr)+0x180000000)
#define CACHE_ADDR2FILE(addr) ((void*)jake_fileoff_to_vaddr(cache_img,(uint64_t)addr-0x180000000))

#endif
