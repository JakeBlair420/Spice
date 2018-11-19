#include <stdio.h>
#include <stdint.h>

#include <mach/mach.h>

enum arg_type {
    ARG_LITERAL,
    ARG_BUFFER,
    ARG_BUFFER_PERSISTENT, // don't free the buffer after the call
    ARG_OUT_BUFFER,
    ARG_INOUT_BUFFER
};

typedef struct _arg_desc {
    uint64_t type;
    uint64_t value;
    uint64_t length;
} arg_desc;

#define REMOTE_LITERAL(val) &(arg_desc){ARG_LITERAL, (uint64_t)val, (uint64_t)0}
#define REMOTE_BUFFER(ptr, size) &(arg_desc){ARG_BUFFER, (uint64_t)ptr, (uint64_t)size}
#define REMOTE_CSTRING(str) &(arg_desc){ARG_BUFFER, (uint64_t)str, (uint64_t)(strlen(str)+1)}

uint64_t remote_alloc(mach_port_t task_port, uint64_t size);
void remote_free(mach_port_t task_port, uint64_t base, uint64_t size);
uint64_t alloc_and_fill_remote_buffer(mach_port_t task_port, uint64_t local_address, uint64_t length);
void remote_read_overwrite(mach_port_t task_port, uint64_t remote_address, uint64_t local_address, uint64_t length);
uint64_t find_gadget_candidate(char **alternatives, size_t gadget_length);
uint64_t find_blr_x19_gadget(void);
uint64_t call_remote(mach_port_t task_port, void *fptr, int n_params, ...);
int inject_library(pid_t pid, const char *path);
