#include <stdbool.h>
#include <mach/mach.h>
#include "common.h"
#include "jailbreak.h"

bool jailbreak(void)
{
    bool retval = false;

#if 0
    mach_port_t server = deja_xnu();
    ASSERT_PORT("deja_xnu", server);
#endif

    retval = true;
out:;
    return retval;
}
