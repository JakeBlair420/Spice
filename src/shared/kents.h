#include <stdint.h>

uint64_t find_csblobs(int pid);
const char *get_current_entitlements(int pid);
int assign_new_entitlements(int pid, const char *new_ents);
