/*
 * pongoOS - https://checkra.in
 *
 * Copyright (C) 2019-2022 checkra1n team
 *
 * This file is part of pongoOS.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */
#ifndef _KERNINFO_H
#define _KERNINFO_H

#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>

#define MAX_BOOTARGS_LEN 256
#define DEFAULT_BOOTARGS "rootdev=md0"
#define DEFAULT_TVOS_BOOTARGS DEFAULT_BOOTARGS " AppleEmbeddedUSBArbitrator-force-usbdevice=1"

#define checkrain_option_none               0x00000000
#define checkrain_option_all                0x7fffffff
#define checkrain_option_failure            0x80000000

// Host options
#define checkrain_option_verbose_logging    (1 << 0)
#define checkrain_option_demote             (1 << 1)
#define checkrain_option_early_exit         (1 << 2)
#define checkrain_option_quick_mode         (1 << 3)

// KPF options
#define checkrain_option_verbose_boot       (1 << 0)
#define checkrain_option_pongo_shell        (1 << 1) /* only a KPF option in autoboot mode */

// Global options
#define checkrain_option_safemode           (1 << 0)
#define checkrain_option_bind_mount         (1 << 1)
#define checkrain_option_force_revert       (1 << 7) /* keep this at 7 */

typedef uint32_t checkrain_option_t, *checkrain_option_p;

typedef enum {
    jailbreak_capability_tfp0               = 1 << 0,
    jailbreak_capability_userspace_reboot   = 1 << 1,
    jailbreak_capability_dyld_ignore_os     = 1 << 2, // TODO: This needs a better name
} jailbreak_capability_t, *jailbreak_capability_p;

#define DEFAULT_CAPABILITIES (jailbreak_capability_tfp0|jailbreak_capability_userspace_reboot)
struct kerninfo {
    uint64_t size;
    uint64_t base;
    uint64_t slide;
    checkrain_option_t flags;
};
struct kpfinfo {
    struct kerninfo k;
    checkrain_option_t kpf_flags;
    char bootargs[MAX_BOOTARGS_LEN];
};

#define checkrain_set_option(options, option, enabled) do { \
    if (enabled)                                            \
        options = (checkrain_option_t)(options | option);   \
    else                                                    \
        options = (checkrain_option_t)(options & ~option);  \
} while (0);

static inline bool checkrain_option_enabled(checkrain_option_t flags, checkrain_option_t opt)
{
    if(flags == checkrain_option_failure)
    {
        switch(opt)
        {
            case checkrain_option_safemode:
                return true;
            default:
                return false;
        }
    }
    return (flags & opt) != 0;
}

#endif
