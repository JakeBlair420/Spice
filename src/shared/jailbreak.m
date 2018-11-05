#include <stdbool.h>
#include <stdint.h>
#include <mach/mach.h>

#include "common.h"
#include "infoleak.h"
#include "pwn.h"

#include "jailbreak.h"

int jailbreak(uint32_t opt)
{
    int retval = -1;
    kern_return_t ret = 0;
    task_t self = mach_task_self(),
           tfp0 = MACH_PORT_NULL;
    kptr_t kbase = 0;
    if(opt & JBOPT_POST_ONLY)
    {
        ret = host_get_special_port(mach_host_self(), HOST_LOCAL_NODE, 4, &tfp0);
        ASSERT_RET_PORT(out, "tfp0", ret, tfp0);
        task_dyld_info_data_t info;
        mach_msg_type_number_t cnt = TASK_DYLD_INFO_COUNT;
        ASSERT_RET(out, "task_info", task_info(tfp0, TASK_DYLD_INFO, (task_info_t)&info, &cnt));
        kbase = info.all_image_info_addr;
    }
    else
    {
        ret = pwn_kernel(&tfp0, &kbase);
        if(ret != KERN_SUCCESS) goto out;
    }

    // TODO: do shit with tfp0 here?

    if(opt & JBOPT_INSTALL_CYDIA)
    {
        // TODO
        if(opt & JBOPT_INSTALL_UNTETHER)
        {
            // TODO: Install untether & register it with dpkg
        }
    }
    else if(opt & JBOPT_INSTALL_UNTETHER)
    {
        // TODO: Install untether without any kind of bootstrap
    }

    // TODO: or do shit with tfp0 here?

    retval = 0;
out:;
    if(MACH_PORT_VALID(tfp0))
    {
        mach_port_deallocate(self, tfp0);
    }
    return retval;
}
