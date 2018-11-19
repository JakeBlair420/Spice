#ifndef JAILBREAK_H
#define JAILBREAK_H

#include <stdint.h>
#include <mach/mach.h>

#include "common.h"

#define JBOPT_POST_ONLY         (1 << 0) /* post-exploitation only */
#define JBOPT_INSTALL_CYDIA     (1 << 1) /* install Cydia */
#define JBOPT_INSTALL_UNTETHER  (1 << 2) /* install untether */

extern offsets_t offs;

extern task_t kernel_task;
extern kptr_t kernel_slide;
extern kptr_t kernproc;

int jailbreak(uint32_t opt);

#endif
