#ifndef OFFSETS_H
#define OFFSETS_H

#ifdef __LP64__
// iPhone6,2 11.4.1
#   define OFF_ANCHOR                0x76199d8 /* TODO: "unable to determine boot cpu!", [x*, 0x78] */
#   define OFF_IOUC_IPC                   0x9c
#   define OFF_TASK_TFLAGS               0x3a0
#   define OFF_TASK_DYLDINFO             0x3a8
#else
// iPhone5,4 10.3.3
#   define OFF_ANCHOR               0xffffffff /* XXX TODO */
#   define OFF_IOUC_IPC                   0x5c
#endif

#endif
