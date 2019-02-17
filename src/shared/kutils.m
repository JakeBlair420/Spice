
#include "kmem.h"
#include "jailbreak.h"

uint64_t find_proc(int pid)
{
    uint64_t proc = kernproc;
    
    while (proc)
    {
        uint32_t proc_pid = rk32(proc + 0x10);
        
        if (proc_pid == pid)
        {
            return proc;
        }
        
        proc = rk64(proc + 0x8);
    }
    
    return 0x0;
}

uint64_t find_proc_by_name(const char *name)
{
    uint64_t proc = kernproc;
    
    while (proc)
    {
        char proc_name[40] = {0};
        
        kread(proc + 0x268, proc_name, sizeof(proc_name));
        
        if (strncmp(proc_name, name, sizeof(proc_name)) == 0)
        {
            return proc;
        }
        
        proc = rk64(proc + 0x8);
    }
    
    return 0x0;
}

uint32_t get_pid_for_name(const char *name)
{
    uint64_t proc = find_proc_by_name(name);
    if (proc == 0x0)
    {
        return 0;
    }
    
    return rk32(proc + 0x10);
}

uint64_t task_self_addr()
{
    uint64_t self_proc = find_proc(getpid());
    LOG("got self_proc = %llx\n", self_proc);
    
    return rk64(self_proc + 0x18);
}

uint64_t find_port_address(mach_port_name_t port)
{
    uint64_t task_port_addr = task_self_addr();
    
    uint64_t itk_space = rk64(task_port_addr + 0x308); // task_t::itk_space
    
    uint64_t is_table = rk64(itk_space + 0x20);
    
    uint32_t port_index = port >> 8;
    
    const int sizeof_ipc_entry_t = 0x18;
    return rk64(is_table + (port_index * sizeof_ipc_entry_t));
}
