#ifndef JAILBREAK_H
#define JAILBREAK_H

#include <stdint.h>

#define JBOPT_POST_ONLY         (1 << 0) /* post-exploitation only */
#define JBOPT_INSTALL_CYDIA     (1 << 1) /* install Cydia */
#define JBOPT_INSTALL_UNTETHER  (1 << 2) /* install untether */

int jailbreak(uint32_t opt);

#endif
