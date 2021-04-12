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

static const soccfg_t* get_soccfg(void)
{
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
    return cfg;
}

typedef struct
{
    const soccfg_t *cfg;
    bool patchedIORVBAR;
    bool patchedAES;
} cb_arg_t;

static int recfg_soc_r32(void *a, uint64_t *addr, uint32_t *mask, uint32_t *data, bool *retry, uint8_t *recnt)
{
    cb_arg_t *arg = a;
    uint64_t ad = *addr;
    uint32_t msk = *mask;
    if(arg->patchedAES && ad == arg->cfg->aes && (msk & 0x7) != 0)
    {
        iprintf("Patching Recfg AES read\n");
        *data = (*data & ~0x7) | (*(volatile uint32_t*)arg->cfg->aes & 0x7 & msk);
        return kRecfgUpdate;
    }
    return kRecfgSuccess;
}

static int recfg_soc_w32(void *a, uint64_t *addr, uint32_t *data)
{
    cb_arg_t *arg = a;
    uint64_t ad = *addr;
    if(ad == arg->cfg->aes)
    {
        iprintf("Patching Recfg AES write\n");
        *data = *(volatile uint32_t*)arg->cfg->aes & 0x7;
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
    for(const uint64_t *ptr = arg->cfg->iorvbar; *ptr != 0; ++ptr)
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
    for(const uint64_t *ptr = arg->cfg->iorvbar; *ptr != 0; ++ptr)
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

void recfg_soc_sync(void)
{
    // Kinda dirty, but works to skip A7/A8/A8X.
    if(!is_16k())
    {
        return;
    }
    // Recfg lock: expected
    if(recfg_locked)
    {
        return;
    }
    iprintf("Patching Recfg sequence\n");
    const soccfg_t *cfg = get_soccfg();
    // Recfg lock: unexpected
    if(*cfg->aop_sram_lock_set || (cfg->aop_cfg_lock && *cfg->aop_cfg_lock))
    {
        panic("Recfg is already locked");
    }
    uint64_t sram_base;
    if(cfg->recfg_base)
    {
        sram_base = cfg->recfg_base;
    }
    else if(cfg->aop_sram_base)
    {
        sram_base = 0x200000000ULL + (uint64_t)*(cfg->aop_sram_base);
    }
    else
    {
        panic("Need either Recfg base or SRAM base");
    }
    uint64_t cfg_base = sram_base + (uint64_t)*(cfg->aop_cfg_table);
#if DEV_BUILD
    iprintf("AOP SRAM: 0x%llx, CFG: 0x%llx\n", sram_base, cfg_base);
#endif
    volatile uint32_t *table = (volatile uint32_t*)cfg_base;
    cb_arg_t arg = { .cfg = cfg };
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
#if DEV_BUILD
        iprintf("Recfg seq %lu: 0x%llx\n", i, seq_base);
#endif
        // Knowing the actual size requires parsing to begin with, so... just set theoretical max.
        size_t seq_size = 0x0001000000000000 - seq_base;

        // If this isn't mapped... well, map it.
        if(vatophys(seq_base) == -1)
        {
            // Map uncached. And just hope that 0x10000 is enough?
            map_range(seq_base & ~0x3fffULL, seq_base & ~0x3fffULL, 0x10000, 2, 0, true);
            // Also adjust max size if we actually can.
            seq_size = (seq_base & ~0x3fffULL) + 0x10000 - seq_base;
        }

#if DEV_BUILD
        volatile uint32_t *p = (volatile uint32_t*)seq_base;
        for(size_t s = 0; s < 0x40; s += 4)
        {
            iprintf("%08x %08x %08x %08x\n", p[s], p[s+1], p[s+2], p[s+3]);
        }
#endif

        // Ideally we'd want to copy MMIO/SRAM to cached DRAM for easier handling, but
        // as mentioned above, getting the size requires parsing already, so that's pointless.
        // The recfg driver was simply modified to only do aligned accesses.
        if(recfg_check((void*)seq_base, seq_size, NULL) == kRecfgSuccess)
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
    if(!is_16k())
    {
        return;
    }
    // We've already been here
    if(recfg_locked)
    {
        return;
    }
    // Last chance to flush anything
    recfg_soc_sync();

    // Actually lock
    const soccfg_t *cfg = get_soccfg();
    *cfg->aop_sram_lock_range = 0;
    *cfg->aop_sram_lock_set = 1;
    if(cfg->aop_cfg_lock)
    {
        *cfg->aop_cfg_lock = 1;
    }
    __asm__ volatile("dsb sy");
    iprintf("Recfg locked\n");
    recfg_locked = true;
}
