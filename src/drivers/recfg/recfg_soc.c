/*
 * pongoOS - https://checkra.in
 *
 * Copyright (C) 2021 checkra1n team
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

#include <pongo.h>

#include "recfg.h"
#include "recfg_soc.h"

extern uint32_t socnum;

typedef struct
{
    uint32_t soc;
    volatile uint32_t *aop_cfg_table;
    volatile uint32_t *aop_sram_base;
    volatile uint32_t *aop_cfg_lock;
    volatile uint32_t *aop_sram_lock_range;
    volatile uint32_t *aop_sram_lock_set;
    uint64_t recfg_base;
    uint64_t recfg_end;
    uint64_t aes;
    const uint64_t *iorvbar;
} soccfg_t;

static const soccfg_t soccfg[] =
{
    {
        .soc = 0x8000,
        .aop_cfg_table       = (volatile uint32_t*)0x210000200,
        .aop_sram_base       = (volatile uint32_t*)0x210800008,
        .aop_cfg_lock        = NULL,
        .aop_sram_lock_range = (volatile uint32_t*)0x21000021c,
        .aop_sram_lock_set   = (volatile uint32_t*)0x210000220,
        .recfg_base = 0,
        .recfg_end  = 0,
        .aes = 0x2102d0000,
        .iorvbar = (uint64_t[]){ 0x202050000, 0x202150000, 0 },
    },
    {
        .soc = 0x8003,
        .aop_cfg_table       = (volatile uint32_t*)0x210000200,
        .aop_sram_base       = (volatile uint32_t*)0x210800008,
        .aop_cfg_lock        = NULL,
        .aop_sram_lock_range = (volatile uint32_t*)0x21000021c,
        .aop_sram_lock_set   = (volatile uint32_t*)0x210000220,
        .recfg_base = 0,
        .recfg_end  = 0,
        .aes = 0x2102d0000,
        .iorvbar = (uint64_t[]){ 0x202050000, 0x202150000, 0 },
    },
    {
        .soc = 0x8001,
        .aop_cfg_table       = (volatile uint32_t*)0x210000200,
        .aop_sram_base       = (volatile uint32_t*)0x210800008,
        .aop_cfg_lock        = NULL,
        .aop_sram_lock_range = (volatile uint32_t*)0x21000021c,
        .aop_sram_lock_set   = (volatile uint32_t*)0x210000220,
        .recfg_base = 0,
        .recfg_end  = 0,
        .aes = 0x2102d0000,
        .iorvbar = (uint64_t[]){ 0x202050000, 0x202150000, 0 },
    },
    {
        .soc = 0x8010,
        .aop_cfg_table       = (volatile uint32_t*)0x210000100,
        .aop_sram_base       = (volatile uint32_t*)0x210800008,
        .aop_cfg_lock        = NULL,
        .aop_sram_lock_range = (volatile uint32_t*)0x21000011c,
        .aop_sram_lock_set   = (volatile uint32_t*)0x210000120,
        .recfg_base = 0,
        .recfg_end  = 0,
        .aes = 0x2102d0000,
        .iorvbar = (uint64_t[]){ 0x202050000, 0x202150000, 0 },
    },
    {
        .soc = 0x8011,
        .aop_cfg_table       = (volatile uint32_t*)0x210000100,
        .aop_sram_base       = (volatile uint32_t*)0x210800008,
        .aop_cfg_lock        = NULL,
        .aop_sram_lock_range = (volatile uint32_t*)0x21000011c,
        .aop_sram_lock_set   = (volatile uint32_t*)0x210000120,
        .recfg_base = 0,
        .recfg_end  = 0,
        .aes = 0x2102d0000,
        .iorvbar = (uint64_t[]){ 0x202050000, 0x202150000, 0x202250000, 0 },
    },
    {
        .soc = 0x8012,
        .aop_cfg_table       = (volatile uint32_t*)0x2112c0200,
        .aop_sram_base       = NULL,
        .aop_cfg_lock        = (volatile uint32_t*)0x2112c0214,
        .aop_sram_lock_range = (volatile uint32_t*)0x211000200,
        .aop_sram_lock_set   = (volatile uint32_t*)0x211000204,
        .recfg_base = 0x211f00000,
        .recfg_end  = 0x211f10000,
        .aes = 0x2112d0000,
        .iorvbar = (uint64_t[]){ 0x202050000, 0x202150000, 0 },
    },
    {
        .soc = 0x8015,
        .aop_cfg_table       = (volatile uint32_t*)0x2352c0200,
        .aop_sram_base       = NULL,
        .aop_cfg_lock        = (volatile uint32_t*)0x2352c0214,
        .aop_sram_lock_range = (volatile uint32_t*)0x235000200,
        .aop_sram_lock_set   = (volatile uint32_t*)0x235000204,
        .recfg_base = 0x235f00000,
        .recfg_end  = 0x235f10000,
        .aes = 0x2352d0000,
        .iorvbar = (uint64_t[]){ 0x208450000, 0x208550000, 0x208050000, 0x208150000, 0x208250000, 0x208350000, 0 },
    },
};

static const soccfg_t *gCFG;

static void get_sram_bounds(uint64_t *sram_base, uint64_t *sram_end)
{
    if(gCFG->recfg_base)
    {
        *sram_base = gCFG->recfg_base;
        *sram_end = gCFG->recfg_end;
    }
    else if(gCFG->aop_sram_base)
    {
        *sram_base = 0x0200000000ULL + (uint64_t)*(gCFG->aop_sram_base);
        // Knowing the actual size requires parsing to begin with, so... just set theoretical max (36bit PA).
        *sram_end  = 0x1000000000ULL;
    }
    else
    {
        panic("Need either Recfg base or SRAM base");
    }
}

static bool recfg_supported(void)
{
    if(socnum == 0x8960 || socnum == 0x7000 || socnum == 0x7001)
    {
        return false;
    }
    return true;
}

typedef struct
{
    bool patchedIORVBAR;
    bool patchedAES;
} cb_arg_t;

static int recfg_soc_r32(void *a, uint64_t *addr, uint32_t *mask, uint32_t *data, bool *retry, uint8_t *recnt)
{
    cb_arg_t *arg = a;
    uint64_t ad = *addr;
    uint32_t msk = *mask;
    if(arg->patchedAES && ad == gCFG->aes && (msk & 0x7) != 0)
    {
        iprintf("Patching Recfg AES read\n");
        *data = (*data & ~0x7) | (*(volatile uint32_t*)gCFG->aes & 0x7 & msk);
        return kRecfgUpdate;
    }
    return kRecfgSuccess;
}

static int recfg_soc_w32(void *a, uint64_t *addr, uint32_t *data)
{
    cb_arg_t *arg = a;
    uint64_t ad = *addr;
    if(ad == gCFG->aes)
    {
        iprintf("Patching Recfg AES write\n");
        *data = *(volatile uint32_t*)gCFG->aes & 0x7;
        arg->patchedAES = true;
        return kRecfgUpdate;
    }
    return kRecfgSuccess;
}

static int recfg_soc_r64(void *a, uint64_t *addr, uint64_t *mask, uint64_t *data, bool *retry, uint8_t *recnt)
{
    cb_arg_t *arg = a;
    uint64_t ad = *addr;
    uint64_t msk = *mask;
    for(const uint64_t *ptr = gCFG->iorvbar; *ptr != 0; ++ptr)
    {
        uint64_t iorvbar = *ptr;
        if(arg->patchedIORVBAR && ad == iorvbar && (msk & 0x0000ffffffffffff) != 0)
        {
            iprintf("Patching Recfg IORVBAR read\n");
            *data = (*data & ~0x0000ffffffffffff) | (*(volatile uint64_t*)iorvbar & 0x0000ffffffffffff & msk);
            return kRecfgUpdate;
        }
    }
    return kRecfgSuccess;
}

static int recfg_soc_w64(void *a, uint64_t *addr, uint64_t *data)
{
    cb_arg_t *arg = a;
    uint64_t ad = *addr;
    for(const uint64_t *ptr = gCFG->iorvbar; *ptr != 0; ++ptr)
    {
        uint64_t iorvbar = *ptr;
        if(ad == iorvbar)
        {
            iprintf("Patching Recfg IORVBAR write\n");
            *data = *(volatile uint64_t*)iorvbar & 0x0000ffffffffffff;
            arg->patchedIORVBAR = true;
            return kRecfgUpdate;
        }
    }
    return kRecfgSuccess;
}

static bool recfg_locked = false;

static uint64_t recfg_map(uint64_t seq_base, uint64_t seq_size)
{
    // If this isn't mapped... well, map it.
    if(vatophys(seq_base) == -1)
    {
        // Map uncached. And just hope that 0x10000 is enough?
        map_range(seq_base & ~0x3fffULL, seq_base & ~0x3fffULL, 0x10000, 2, 0, true);
        // Also adjust max size if we actually can.
        uint64_t size = (seq_base & ~0x3fffULL) + 0x10000 - seq_base;
        if(size < seq_size)
        {
            seq_size = size;
        }
    }
    return seq_size;
}

void recfg_soc_sync(void)
{
    // Skip A7/A8/A8X.
    if(!recfg_supported())
    {
        return;
    }
    // Recfg lock: expected
    if(recfg_locked)
    {
        return;
    }
    iprintf("Patching Recfg sequence\n");
    // Recfg lock: unexpected
    if(*gCFG->aop_sram_lock_set || (gCFG->aop_cfg_lock && *gCFG->aop_cfg_lock))
    {
        panic("Recfg is already locked");
    }
    uint64_t sram_base, sram_end;
    get_sram_bounds(&sram_base, &sram_end);
    uint64_t cfg_base = sram_base + (uint64_t)*(gCFG->aop_cfg_table);
    volatile uint32_t *table = (volatile uint32_t*)cfg_base;
    cb_arg_t arg = {};
    recfg_cb_t cb =
    {
        .r32 = &recfg_soc_r32,
        .r64 = &recfg_soc_r64,
        .w32 = &recfg_soc_w32,
        .w64 = &recfg_soc_w64,
    };
    for(size_t i = 0; i < 8; ++i)
    {
        uint64_t seq_base = (uint64_t)table[i] << 4;
        size_t seq_size = sram_end - seq_base;
        seq_size = recfg_map(seq_base, seq_size);

        // Ideally we'd want to copy MMIO/SRAM to cached DRAM for easier handling, but
        // as mentioned above, getting the size requires parsing already, so that's pointless.
        // The recfg driver was simply modified to only do aligned accesses.
        if(recfg_check((void*)seq_base, seq_size, NULL, false) == kRecfgSuccess)
        {
            // Normally we'd want to panic if recfg_check() fails, but it turns out
            // certain sequences are unused and can be completely uninitialised
            // with SRAM holding whatever contents it had on power-on.
            arg.patchedIORVBAR = false;
            arg.patchedAES     = false;
            int r = recfg_walk((void*)seq_base, seq_size, &cb, &arg);
            if(r != kRecfgSuccess && r != kRecfgUpdate)
            {
                // We DO however want to panic if any of the callbacks attempted something that we couldn't support.
                panic("recfg_walk(%lu) returned: %d", i, r);
            }
        }
    }
    __asm__ volatile("dsb sy");
    iprintf("Recfg done\n");
}

void recfg_soc_lock(void)
{
    // Skip A7/A8/A8X.
    if(!recfg_supported())
    {
        return;
    }
    // We've already been here
    if(recfg_locked)
    {
        return;
    }
    // Last chance to flush anything
    // This will also take care of panicing if we're unexpectedly locked already
    recfg_soc_sync();

    // Actually lock
    uint64_t sram_base, sram_end;
    get_sram_bounds(&sram_base, &sram_end);
    uint64_t lockdown_max = sram_base + 0x200000;
    if(sram_end < lockdown_max)
    {
        lockdown_max = sram_end;
    }
    uint64_t min = sram_base + *gCFG->aop_cfg_table;
    uint64_t max = min + 0x20;
    volatile uint32_t *table = (volatile uint32_t*)min;
    uint64_t seq_max = max;
    for(size_t i = 0; i < 8; ++i)
    {
        uint64_t seq_base = (uint64_t)table[i] << 4;
        if(seq_base >= sram_base && seq_base <= lockdown_max)
        {
            if(seq_base < min)     min     = seq_base;
            if(seq_base > seq_max) seq_max = seq_base;
        }
    }
    if(seq_max > max)
    {
        size_t seq_size = lockdown_max - seq_max;
        // recfg_soc_sync should've mapped already
        size_t off = 0;
        if(recfg_check((void*)seq_max, seq_size, &off, false) != kRecfgSuccess)
        {
            // If the sequence is invalid, we still wanna lock down everything before it
            off = 0;
        }
        max = seq_max + off + 4;
    }
    if(max % 0x40 == 0) max -= 0x40;
    *gCFG->aop_sram_lock_range = ((((max - sram_base) >> 6) & 0x7fff) << 16) | (((min - sram_base) >> 6) & 0x7fff);
    *gCFG->aop_sram_lock_set = 1;
    if(gCFG->aop_cfg_lock)
    {
        *gCFG->aop_cfg_lock = 1;
    }
    __asm__ volatile("dsb sy");
    iprintf("Recfg locked\n");
    recfg_locked = true;
}

struct recfg_command
{
    const char* name;
    const char* desc;
    void (*cb)(const char *cmd, char *args);
};

static void recfg_cmd_help(const char *cmd, char *args);
static void recfg_cmd_dump(const char *cmd, char *args);
static void recfg_cmd_sync(const char *cmd, char *args);
static void recfg_cmd_lock(const char *cmd, char *args);

static const struct recfg_command command_table[] =
{
    {"help", "show usage", recfg_cmd_help},
    {"dump", "print recfg sequences", recfg_cmd_dump},
    {"sync", "flush MMIO changes to recfg sequences", recfg_cmd_sync},
    {"lock", "sync and lock recfg sequences", recfg_cmd_lock},
};

static void recfg_cmd_help(const char *cmd, char *args)
{
    iprintf("recfg usage: recfg [subcommand]\nsubcommands:\n");
    for(size_t i = 0; i < sizeof(command_table) / sizeof(command_table[0]); ++i)
    {
        iprintf("%8s | %s\n", command_table[i].name, command_table[i].desc);
    }
}

static int recfg_end_cb(void *a)
{
    iprintf("    end\n");
    return kRecfgSuccess;
}

static int recfg_delay_cb(void *a, uint32_t *delay)
{
    iprintf("    delay %d\n", *delay);
    return kRecfgSuccess;
}

static int recfg_read32_cb(void *a, uint64_t *addr, uint32_t *mask, uint32_t *data, bool *retry, uint8_t *recnt)
{
    if(*retry)  iprintf("    rd32 0x%09llx & 0x%08x == 0x%08x, retry = %d\n", *addr, *mask, *data, *recnt);
    else        iprintf("    rd32 0x%09llx & 0x%08x == 0x%08x\n", *addr, *mask, *data);
    return kRecfgSuccess;
}

static int recfg_read64_cb(void *a, uint64_t *addr, uint64_t *mask, uint64_t *data, bool *retry, uint8_t *recnt)
{
    if(*retry)  iprintf("    rd64 0x%09llx & 0x%016llx == 0x%016llx, retry = %d\n", *addr, *mask, *data, *recnt);
    else        iprintf("    rd64 0x%09llx & 0x%016llx == 0x%016llx\n", *addr, *mask, *data);
    return kRecfgSuccess;
}

static int recfg_write32_cb(void *a, uint64_t *addr, uint32_t *data)
{
    iprintf("    wr32 0x%09llx = 0x%08x\n", *addr, *data);
    return kRecfgSuccess;
}

static int recfg_write64_cb(void *a, uint64_t *addr, uint64_t *data)
{
    iprintf("    wr64 0x%llx = 0x%016llx\n", *addr, *data);
    return kRecfgSuccess;
}

static void recfg_cmd_dump(const char *cmd, char *args)
{
    uint64_t sram_base, sram_end;
    get_sram_bounds(&sram_base, &sram_end);
    uint64_t cfg_base = sram_base + (uint64_t)*(gCFG->aop_cfg_table);
    volatile uint32_t *table = (volatile uint32_t*)cfg_base;
    bool sram_locked = *gCFG->aop_sram_lock_set != 0;
    bool cfg_locked = gCFG->aop_cfg_lock ? *gCFG->aop_cfg_lock != 0 : sram_locked;
    uint32_t lock_val = *gCFG->aop_sram_lock_range;
    uint64_t lock_from = sram_base + ((lock_val & 0xffff) << 6);
    uint64_t lock_to   = sram_base + (((lock_val >> 16) & 0xffff) << 6) + 0x40;
    iprintf("CFG table: 0x%llx (%s)\n", cfg_base,  cfg_locked  ? "locked" : "unlocked");
    iprintf("SRAM base: 0x%llx (%s)\n", sram_base, sram_locked ? "locked" : "unlocked");
    if(lock_to <= lock_from)
    {
        iprintf("SRAM lock range: none (%s)\n", sram_locked ? "locked" : "unlocked");
    }
    else
    {
        iprintf("SRAM lock range: 0x%llx-0x%llx (%s)\n", lock_from, lock_to, sram_locked ? "locked" : "unlocked");
    }
    recfg_cb_t cb =
    {
        .generic = NULL,
        .end     = recfg_end_cb,
        .delay   = recfg_delay_cb,
        .r32     = recfg_read32_cb,
        .r64     = recfg_read64_cb,
        .w32     = recfg_write32_cb,
        .w64     = recfg_write64_cb,
    };
    for(size_t i = 0; i < 8; ++i)
    {
        uint64_t seq_base = (uint64_t)table[i] << 4;
        size_t seq_size = sram_end - seq_base;
        seq_size = recfg_map(seq_base, seq_size);
        iprintf("Recfg seq %lu: 0x%llx\n", i, seq_base);

        if(recfg_check((void*)seq_base, seq_size, NULL, true) == kRecfgSuccess)
        {
            int r = recfg_walk((void*)seq_base, seq_size, &cb, NULL);
            if(r != kRecfgSuccess)
            {
                // We DO however want to panic if any of the callbacks attempted something that we couldn't support.
                panic("recfg_walk(%lu) returned: %d", i, r);
            }
        }
    }
}

static void recfg_cmd_sync(const char *cmd, char *args)
{
    if(recfg_locked)
    {
        iprintf("Sorry, recfg sequences are already locked.\n");
        return;
    }
    recfg_soc_sync();
}

static void recfg_cmd_lock(const char *cmd, char *args)
{
    if(recfg_locked)
    {
        iprintf("Recfg sequences are already locked.\n");
        return;
    }
    recfg_soc_lock();
}

static void recfg_cmd(const char* cmd, char *args)
{
    char *arguments = command_tokenize(args, 0x1ff - (args - cmd));
    if(arguments)
    {
        for(size_t i = 0; i < sizeof(command_table) / sizeof(command_table[0]); ++i)
        {
            if(strcmp(args, command_table[i].name) == 0)
            {
                command_table[i].cb(args, arguments);
                return;
            }
        }
        if(args[0] != '\0')
        {
            iprintf("recfg: invalid command %s\n", args);
        }
        recfg_cmd_help(cmd, arguments);
    }
}

void recfg_soc_setup(void)
{
    // This saves us from having to check in each cmd callback
    if(!recfg_supported())
    {
        return;
    }

    const soccfg_t *cfg = NULL;
    for(size_t i = 0; i < sizeof(soccfg)/sizeof(soccfg[0]); ++i)
    {
        if(soccfg[i].soc == socnum)
        {
            cfg = &soccfg[i];
            break;
        }
    }
    if(!cfg)
    {
        panic("Failed to find SoC Recfg info");
    }
    gCFG = cfg;

    command_register("recfg", "recfg sequences", recfg_cmd);
}
