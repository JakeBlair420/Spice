#include <stdbool.h>
#include <mach/mach.h>
#include "common.h"
#include "deja_xnu.h"
#include "jailbreak.h"

bool jailbreak(void)
{
    bool retval = false;

    mach_port_t server = deja_xnu();
    ASSERT_PORT("deja_xnu", server);

    retval = true;
out:;
    return retval;
}
