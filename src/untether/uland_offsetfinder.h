#ifndef ULAND_OFFSETFINDER_H
#define ULAND_OFFSETFINDER_H

void * racoon_bin;
size_t racoon_bin_size;
void * shared_cache;
size_t shared_cache_size;

void * find_data_raw(void * bin, size_t bin_size, void * data, size_t data_size,int search_aligned);
void * find_str(char * str);
void * find_ref(void * addr);
void * find_code_xref(void * addr);
void * isakmp_cfg_config_addr();
void * lcconf_addr();
size_t get_cache_maxslide();
void * memmove_cache_ptr(char * path);
void * get_stackpivot_addr(char * path);
void * get_cbz_x0_gadget();
void * get_cbz_x0_x16_load(void * cbz_x0_gadget_addr);
void * get_errno_offset(char * path);
#define find_data(bin,bin_size,data,data_size) find_data_raw(bin,bin_size,data,data_size,1)

#endif
