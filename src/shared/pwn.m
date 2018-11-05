#include <mach/mach.h>

#include "common.h"
#include "kdata.h"

#include "pwn.h"

// TODO: separate func to go from half-baked tfp0 to real one

kern_return_t pwn_kernel(task_t *tfp0, kptr_t *kbase)
{
    kern_return_t retval = KERN_FAILURE;

    kptr_t kaddr = kdata_init();
    if(!kaddr) goto out;

    // TODO

    retval = KERN_SUCCESS;
out:;
    return retval;
}
