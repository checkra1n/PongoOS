#include <pongo.h>

#include "recfg.h"
#include "recfg_soc.h"

extern uint32_t socnum;

typedef struct
{
    uint32_t soc;
    volatile uint32_t *aop_cfg_table;
    volatile uint32_t *aop_sram_base;
    uint64_t recfg_base;
    uint64_t recfg_end;
    uint64_t aes;
    uint64_t *iorvbar;
} soccfg_t;

static const soccfg_t soccfg[] =
{
    {
        .soc = 0x8000,
        .aop_cfg_table = (volatile uint32_t*)0x210000200,
        .aop_sram_base = (volatile uint32_t*)0x210800008,
        .recfg_base = 0,
        .recfg_end  = 0,
        .aes = 0x2102d0000,
        .iorvbar = (uint64_t[]){ 0x202050000, 0x202150000, 0 },
    },
    {
        .soc = 0x8003,
        .aop_cfg_table = (volatile uint32_t*)0x210000200,
        .aop_sram_base = (volatile uint32_t*)0x210800008,
        .recfg_base = 0,
        .recfg_end  = 0,
        .aes = 0x2102d0000,
        .iorvbar = (uint64_t[]){ 0x202050000, 0x202150000, 0 },
    },
    {
        .soc = 0x8001,
        .aop_cfg_table = (volatile uint32_t*)0x210000200,
        .aop_sram_base = (volatile uint32_t*)0x210800008,
        .recfg_base = 0,
        .recfg_end  = 0,
        .aes = 0x2102d0000,
        .iorvbar = (uint64_t[]){ 0x202050000, 0x202150000, 0 },
    },
    {
        .soc = 0x8010,
        .aop_cfg_table = (volatile uint32_t*)0x210000100,
        .aop_sram_base = (volatile uint32_t*)0x210800008,
        .recfg_base = 0,
        .recfg_end  = 0,
        .aes = 0x2102d0000,
        .iorvbar = (uint64_t[]){ 0x202050000, 0x202150000, 0 },
    },
    {
        .soc = 0x8011,
        .aop_cfg_table = (volatile uint32_t*)0x210000100,
        .aop_sram_base = (volatile uint32_t*)0x210800008,
        .recfg_base = 0,
        .recfg_end  = 0,
        .aes = 0x2102d0000,
        .iorvbar = (uint64_t[]){ 0x202050000, 0x202150000, 0x202250000, 0 },
    },
    {
        .soc = 0x8015,
        .aop_cfg_table = (volatile uint32_t*)0x2352c0200,
        .aop_sram_base = NULL,
        .recfg_base = 0x235f00000,
        .recfg_end  = 0x235f0a000,
        .aes = 0x2352d0000,
        .iorvbar = (uint64_t[]){ 0x208450000, 0x208550000, 0x208050000, 0x208150000, 0x208250000, 0x208350000, 0 },
    },
};

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
    for(uint64_t *ptr = arg->cfg->iorvbar; *ptr != 0; ++ptr)
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
    for(uint64_t *ptr = arg->cfg->iorvbar; *ptr != 0; ++ptr)
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

void recfg_soc_update(void)
{
    if(!is_16k())
    {
        return;
    }
    iprintf("Patching Recfg requence\n");
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
        iprintf("WARNING: Failed to find SoC Recfg info\n");
        return;
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
        iprintf("WARNING: Need either Recfg base or SRAM base\n");
        return;
    }
    uint64_t cfg_base = sram_base + (uint64_t)*(cfg->aop_cfg_table);
    iprintf("AOP SRAM: 0x%llx, CFG: 0x%llx\n", sram_base, cfg_base);
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
        // recfg_check() prints its own messages on failure.
        // Ideally we'd treat SRAM as volatile & copy it into a buffer and back,
        // but getting the right size to copy is a pain, so ehhh whatever.
        // Also ugly hack to specify biggest size we reasonably can. It's fiiine. Trust me.
        if(recfg_check((void*)seq_base, 0xfffffffffffffffc - seq_base, NULL) == kRecfgSuccess)
        {
            arg.patchedIORVBAR = false;
            arg.patchedAES     = false;
            recfg_walk((void*)seq_base, 0xfffffffffffffffc - seq_base, &cb, &arg);
        }
    }
    __asm__ volatile("dmb sy");
    iprintf("Recfg done\n");
}
