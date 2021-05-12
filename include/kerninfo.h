/* 
 * pongoOS - https://checkra.in
 * 
 * Copyright (C) 2019-2021 checkra1n team
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

typedef enum {
    checkrain_option_none               = 0,
    checkrain_option_all                = -1,
    checkrain_option_failure            = -2,

    checkrain_option_safemode           = 1 << 0,
    checkrain_option_verbose_boot       = 1 << 1,
    checkrain_option_verbose_logging    = 1 << 2,
    checkrain_option_demote             = 1 << 3,
    checkrain_option_pongo_shell        = 1 << 4,
    checkrain_option_early_exit         = 1 << 5,
} checkrain_option_t, *checkrain_option_p;

struct kerninfo {
    uint64_t size;
    uint64_t base;
    uint64_t slide;
    checkrain_option_t flags;
    uint16_t cpid;
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
