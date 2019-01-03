#include <stddef.h>             // size_t
#include <strings.h>            // bcopy
#include <sys/mman.h>           // mlock
#include <mach/mach.h>

#include "common.h"
#include "infoleak.h"

#include "kdata.h"

static kptr_t kdata_addr = 0;
static thread_t kdata_worker = MACH_PORT_NULL;
static mach_vm_address_t kdata_shm = 0;

kptr_t kdata_init(void)
{
    if(0) // TODO: SMAP devices
    {
        kptr_t kslide = get_kernel_slide();
        if(!kslide) goto out;
        // TODO: pull SBX & get thread handle
        // TODO: create shm
        // TODO: kdata_addr = SOMETHING + kslide;
    }
    else // Non-SMAP devices
    {
        mach_vm_address_t addr = 0;
        ASSERT_RET(out, "mach_vm_allocate", mach_vm_allocate(mach_task_self(), &addr, KDATA_SIZE, VM_FLAGS_ANYWHERE));
        bzero((void *)addr, KDATA_SIZE);
        int r = mlock((void*)addr, KDATA_SIZE);
        LOG("mlock: %u", r);
        if(r != 0) goto out;
        kdata_addr = addr;
    }
out:;
    return kdata_addr;
}

kern_return_t kdata_write(const void *data)
{
    if(MACH_PORT_VALID(kdata_worker)) // SMAP devices
    {
        bcopy(data, (void*)kdata_shm, KDATA_SIZE);
        kern_return_t ret = KERN_FAILURE;
        // TODO: call worker
        ret = KERN_SUCCESS;
    out:;
        return ret;
    }
    else // Non-SMAP devices
    {
        bcopy(data, (void*)kdata_addr, KDATA_SIZE);
        return KERN_SUCCESS;
    }
}

kern_return_t kdata_read(void *buffer)
{
    if (MACH_PORT_VALID(kdata_worker)) // SMAP devices
    {
        kern_return_t ret = KERN_FAILURE;
        // TODO: call worker
        ret = KERN_SUCCESS;
        bcopy((void *)kdata_shm, buffer, KDATA_SIZE);
    out:;
        return ret;
    }
    else // Non-SMAP devices 
    {
        bcopy((void *)kdata_addr, buffer, KDATA_SIZE);
        return KERN_SUCCESS;
    }
}

void kdata_cleanup(void)
{
    if(kdata_worker)
    {
        // TODO: destroy thread
        // TODO: dealloc shm
    }
    else if(kdata_addr)
    {
        mach_vm_deallocate(mach_task_self(), kdata_addr, KDATA_SIZE);
    }
    kdata_addr = 0;
}
