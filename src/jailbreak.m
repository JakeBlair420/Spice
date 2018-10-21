#include <stdbool.h>
#include <mach/mach.h>
#include "backboardd.h"
#include "common.h"
#include "jailbreak.h"

bool jailbreak(void)
{
    bool retval = false;

    mach_port_t server = pwn_backboardd();
    ASSERT_PORT("pwn_backboardd", server);

    retval = true;
out:;
    return retval;
}
