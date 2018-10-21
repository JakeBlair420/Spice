#ifndef HID_H
#define HID_H

#include <stdint.h>
#include <mach/mach.h>

extern kern_return_t io_hideventsystem_open(mach_port_t server, task_t task, uint32_t type, void *bplist, uint32_t bplist_len, uint32_t unk0, uint32_t unk1, mach_port_t reply, mach_port_t* client);
extern kern_return_t io_hideventsystem_clear_service_cache(mach_port_t client);
extern kern_return_t io_hideventsystem_copy_matching_services(mach_port_t client, void *matching, uint32_t matching_len, mach_vm_address_t *matching_out, uint32_t *matching_out_len, mach_vm_address_t *service_ids_out, uint32_t *service_ids_out_len);
extern kern_return_t io_hideventsystem_queue_create(mach_port_t client, mach_port_t notify, uint32_t queue_size, mem_entry_name_port_t *object);
extern kern_return_t io_hideventsystem_queue_start(mach_port_t client);
extern kern_return_t io_hideventsystem_queue_stop(mach_port_t client);

#endif
