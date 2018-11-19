#include <mach/mach.h>

uint64_t find_proc(int pid);
uint64_t find_proc_by_name(const char *name);
uint32_t get_pid_for_name(const char *name);

uint64_t task_self_addr();
uint64_t find_port_address(mach_port_name_t port);
