#include <stdbool.h>
#include <mach/mach.h>

#include "common.h"
#include "infoleak.h"
#include "panic.h"

#include "jailbreak.h"



bool jailbreak(void)
{
    bool retval = false;

    kptr_t kslide = get_kernel_slide();
    if(!kslide) goto out;

#if 0
    mach_port_t server = deja_xnu();
    ASSERT_PORT("deja_xnu", server);
#endif

    retval = true;
out:;
    return retval;
}
