#ifndef COMMON_H
#define COMMON_H

#import <Foundation/Foundation.h>
#include <mach/mach.h>

#ifdef RELEASE
#   define LOG(str, args...) do { } while(0)
#else
#   define LOG(str, args...) do { NSLog(@ str "\n", ##args); } while(0)
#endif

#define ASSERT_RET(str, ret) \
do \
{ \
    kern_return_t _ret = (ret); \
    LOG(str ": %s", mach_error_string(_ret)); \
    if(_ret != KERN_SUCCESS) goto out; \
} while(0)
#define ASSERT_PORT(str, port) \
do \
{ \
    mach_port_t _port = (port); \
    LOG(str ": %x", _port); \
    if(!MACH_PORT_VALID(_port)) goto out; \
} while(0)
#define ASSERT_RET_PORT(str, ret, port) \
do \
{ \
    kern_return_t _ret = (ret); \
    mach_port_t _port = (port); \
    LOG(str ": %x, %s", _port, mach_error_string(_ret)); \
    if(_ret != KERN_SUCCESS || !MACH_PORT_VALID(_port)) goto out; \
} while(0)

#define ADDR "0x%llx"

extern kern_return_t bootstrap_look_up(mach_port_t bp, char *name, mach_port_t *sp);
extern mach_port_t mach_reply_port(void);
extern kern_return_t mach_vm_map(task_t task, mach_vm_address_t *addr, mach_vm_size_t size, mach_vm_offset_t mask, int flags, mem_entry_name_port_t object, memory_object_offset_t offset, boolean_t copy, vm_prot_t cur, vm_prot_t max, vm_inherit_t inheritance);
extern kern_return_t mach_vm_deallocate(task_t task, mach_vm_address_t address, mach_vm_size_t size);

#endif
