#include <mach/mach.h>

#include "common.h"

mach_port_t prepare_user_client(void);

kern_return_t init_kexecute(kptr_t zone_map, kptr_t add_ret_gadget);
void term_kexecute(void);

kptr_t kexecute(kptr_t addr, int n_args, ...);
kptr_t zm_fix_addr(kptr_t addr);
