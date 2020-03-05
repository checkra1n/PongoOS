// ---------- modified ----------

#include <pongo.h>

#define ERR(str, args...) do { iprintf("Recfg ERR: " str "\n", ##args); } while(0)

#define REQ(expr) \
do \
{ \
    if(!(expr)) \
    { \
        ERR("!(" #expr ")"); \
        goto out; \
    } \
} while(0)

#define RECFG_REAL_ADDR

// ---------- modified end ----------

#include <stdbool.h>
#include <stddef.h>             // size_t
#include <stdint.h>

#include "recfg.h"

int recfg_check(void *mem, size_t size, size_t *offp)
{
    int retval = kRecfgFailure;
    char *start = mem,
         *end   = start + size;
    recfg_cmd_t *cmd = mem;
    while(end - (char*)cmd != 0) // != rather than > because ptrdiff is signed
    {
        REQ(end - (char*)cmd >= sizeof(recfg_cmd_t));
        switch(cmd->cmd)
        {
            case kRecfgMeta:
                switch(cmd->meta)
                {
                    case kRecfgEnd:
                        REQ(cmd->data == 0);
                        goto end;
                    case kRecfgDelay:
                        break;
                    default:
                        REQ(false);
                }
                cmd = cmd + 1;
                break;
            case kRecfgRead:
                REQ(end - (char*)cmd >= sizeof(recfg_read_t));
                recfg_read_t *read = (recfg_read_t*)cmd;
                REQ(read->count == 0);
                // This can happen, and doesn't matter, I guess
                //REQ(read->retry || read->recnt == 0);
                // This also happens, but I'm pretty sure Apple fucked up
                //REQ(read->__res == 0);
                if(!read->large)
                {
                    REQ(end - (char*)cmd >= sizeof(recfg_read32_t));
                    cmd = (recfg_cmd_t*)((recfg_read32_t*)read + 1);
                }
                else
                {
                    REQ(end - (char*)cmd >= sizeof(recfg_read64_t) + 2 * sizeof(uint64_t));
                    recfg_read64_t *r64 = (recfg_read64_t*)read;
                    uint32_t *tmp = r64->__aux;
                    if(
                        *tmp == 0xdeadbeef
#ifdef RECFG_REAL_ADDR
                        // In real memory, 64-bit stuff has to be 64-bit aligned.
                        // When extracted from iBoot though, it only has to be 32-bit aligned.
                        && ((uintptr_t)tmp & 0x4) != 0
#endif
                    )
                    {
                        REQ(end - (char*)cmd >= sizeof(recfg_read64_t) + 2 * sizeof(uint64_t) + sizeof(uint32_t));
                        ++tmp;
                    }
                    uint64_t *datap = (uint64_t*)tmp;
                    cmd = (recfg_cmd_t*)(datap + 2);
                }
                break;
            case kRecfgWrite32:
                {
                    uint32_t cnt, alcnt;
                    REQ(end - (char*)cmd >= sizeof(recfg_write32_t));
                    recfg_write32_t *w32 = (recfg_write32_t*)cmd;
                    cnt = w32->count + 1;
                    alcnt = (cnt + 3) & ~3;
                    REQ(cnt <= 16 && alcnt <= 16 && (alcnt & 3) == 0); // Sanity
                    REQ(end - (char*)cmd >= sizeof(recfg_write32_t) + alcnt * sizeof(uint8_t) + cnt * sizeof(uint32_t));
                    cmd = (recfg_cmd_t*)((uint32_t*)(w32->off + alcnt) + cnt);
                }
                break;
            case kRecfgWrite64:
                {
                    uint32_t cnt, alcnt;
                    REQ(end - (char*)cmd >= sizeof(recfg_write64_t));
                    recfg_write64_t *w64 = (recfg_write64_t*)cmd;
                    cnt = w64->count + 1;
                    alcnt = (cnt + 3) & ~3;
                    REQ(cnt <= 16 && alcnt <= 16 && (alcnt & 3) == 0); // Sanity
                    REQ(end - (char*)cmd >= sizeof(recfg_write64_t) + alcnt * sizeof(uint8_t) + cnt * sizeof(uint64_t));
                    uint32_t *tmp = (uint32_t*)(w64->off + alcnt);
                    if(
                        *tmp == 0xdeadbeef
#ifdef RECFG_REAL_ADDR
                        // In real memory, 64-bit stuff has to be 64-bit aligned.
                        // When extracted from iBoot though, it only has to be 32-bit aligned.
                        && ((uintptr_t)tmp & 0x4) != 0
#endif
                    )
                    {
                        REQ(end - (char*)cmd >= sizeof(recfg_write64_t) + alcnt * sizeof(uint8_t) + sizeof(uint32_t) + cnt * sizeof(uint64_t));
                        ++tmp;
                    }
                    uint64_t *datap = (uint64_t*)tmp;
                    cmd = (recfg_cmd_t*)(datap + cnt);
                }
                break;
            default:
                // This should REALLY be unreachable, but I don't trust anything in this world.
                REQ(false);
        }
    }
end:;
    retval = kRecfgSuccess;

out:;
    if(offp) *offp = (char*)cmd - start;
    return retval;
}

int recfg_walk(void *mem, size_t size, const recfg_cb_t *cb, void *a)
{
    int retval = kRecfgFailure,
        ret    = kRecfgSuccess;
    char *start = mem,
         *end   = start + size;
    recfg_cmd_t *cmd = mem;
    while(end - (char*)cmd != 0) // != rather than > because ptrdiff is signed
    {
        if(cb->generic)
        {
            int r = cb->generic(a, cmd);
            REQ(r != kRecfgUpdate);
            if(r != kRecfgSuccess)
            {
                retval = r;
                goto out;
            }
        }
        switch(cmd->cmd)
        {
            case kRecfgMeta:
                switch(cmd->meta)
                {
                    case kRecfgEnd:
                        if(cb->end)
                        {
                            int r = cb->end(a);
                            REQ(r != kRecfgUpdate);
                            if(r != kRecfgSuccess)
                            {
                                retval = r;
                                goto out;
                            }
                        }
                        goto end;
                    case kRecfgDelay:
                        if(cb->delay)
                        {
                            uint32_t data = cmd->data;
                            int r = cb->delay(a, &data);
                            if(r == kRecfgUpdate)
                            {
                                REQ(data < (1 << 26));
                                cmd->data = data;
                                ret |= kRecfgUpdate;
                            }
                            else if(r != kRecfgSuccess)
                            {
                                retval = r;
                                goto out;
                            }
                        }
                        break;
                    default:
                        goto out;
                }
                cmd = cmd + 1;
                break;
            case kRecfgRead:
                {
                    recfg_read_t *read = (recfg_read_t*)cmd;
                    if(!read->large)
                    {
                        recfg_read32_t *r32 = (recfg_read32_t*)read;
                        if(cb->r32)
                        {
                            uint64_t addr = ((uint64_t)r32->base << 10) | ((uint64_t)r32->off << 2);
                            uint32_t mask = r32->mask;
                            uint32_t data = r32->data;
                            bool retry = !!r32->retry;
                            uint8_t recnt = r32->recnt;
                            int r = cb->r32(a, &addr, &mask, &data, &retry, &recnt);
                            if(r == kRecfgUpdate)
                            {
                                REQ((addr & 0xfffffff000000003) == 0);
                                r32->base = addr >> 10;
                                r32->off = (addr >> 2) & 0xff;
                                r32->mask = mask;
                                r32->data = data;
                                r32->retry = retry ? 1 : 0;
                                r32->recnt = recnt;
                                ret |= kRecfgUpdate;
                            }
                            else if(r != kRecfgSuccess)
                            {
                                retval = r;
                                goto out;
                            }
                        }
                        cmd = (recfg_cmd_t*)(r32 + 1);
                    }
                    else
                    {
                        recfg_read64_t *r64 = (recfg_read64_t*)read;
                        uint32_t *tmp = r64->__aux;
                        if(
                            *tmp == 0xdeadbeef
#ifdef RECFG_REAL_ADDR
                            // In real memory, 64-bit stuff has to be 64-bit aligned.
                            // When extracted from iBoot though, it only has to be 32-bit aligned.
                            && ((uintptr_t)tmp & 0x4) != 0
#endif
                        )
                        {
                            ++tmp;
                        }
                        uint64_t *datap = (uint64_t*)tmp;
                        if(cb->r64)
                        {
                            uint64_t addr = ((uint64_t)r64->base << 10) | ((uint64_t)r64->off << 2);
                            uint64_t mask = datap[0];
                            uint64_t data = datap[1];
                            bool retry = !!r64->retry;
                            uint8_t recnt = r64->recnt;
                            int r = cb->r64(a, &addr, &mask, &data, &retry, &recnt);
                            if(r == kRecfgUpdate)
                            {
                                REQ((addr & 0xfffffff000000003) == 0);
                                r64->base = addr >> 10;
                                r64->off = (addr >> 2) & 0xff;
                                datap[0] = mask;
                                datap[1] = data;
                                r64->retry = retry ? 1 : 0;
                                r64->recnt = recnt;
                                ret |= kRecfgUpdate;
                            }
                            else if(r != kRecfgSuccess)
                            {
                                retval = r;
                                goto out;
                            }
                        }
                        cmd = (recfg_cmd_t*)(datap + 2);
                    }
                }
                break;
            case kRecfgWrite32:
                {
                    uint32_t cnt, alcnt;
                    recfg_write32_t *w32 = (recfg_write32_t*)cmd;
                    cnt = w32->count + 1;
                    alcnt = (cnt + 3) & ~3;
                    uint32_t *datap = (uint32_t*)(w32->off + alcnt);
                    if(cb->w32)
                    {
                        for(uint32_t i = 0; i < cnt; ++i)
                        {
                            uint64_t addr = ((uint64_t)w32->base << 10) | ((uint64_t)w32->off[i] << 2);
                            uint32_t data = datap[i];
                            int r = cb->w32(a, &addr, &data);
                            if(r == kRecfgUpdate)
                            {
                                REQ((addr & 0xfffffff000000003) == 0);
                                if(cnt == 1)
                                {
                                    w32->base = addr >> 10;
                                }
                                else
                                {
                                    REQ((addr & 0xffffffc00) == (w32->base << 10));
                                }
                                w32->off[i] = (addr >> 2) & 0xff;
                                datap[i] = data;
                                ret |= kRecfgUpdate;
                            }
                            else if(r != kRecfgSuccess)
                            {
                                retval = r;
                                goto out;
                            }
                        }
                    }
                    cmd = (recfg_cmd_t*)(datap + cnt);
                }
                break;
            case kRecfgWrite64:
                {
                    uint32_t cnt, alcnt;
                    recfg_write64_t *w64 = (recfg_write64_t*)cmd;
                    cnt = w64->count + 1;
                    alcnt = (cnt + 3) & ~3;
                    uint32_t *tmp = (uint32_t*)(w64->off + alcnt);
                    if(
                        *tmp == 0xdeadbeef
#ifdef RECFG_REAL_ADDR
                        // In real memory, 64-bit stuff has to be 64-bit aligned.
                        // When extracted from iBoot though, it only has to be 32-bit aligned.
                        && ((uintptr_t)tmp & 0x4) != 0
#endif
                    )
                    {
                        ++tmp;
                    }
                    uint64_t *datap = (uint64_t*)tmp;
                    if(cb->w64)
                    {
                        for(uint32_t i = 0; i < cnt; ++i)
                        {
                            uint64_t addr = ((uint64_t)w64->base << 10) | ((uint64_t)w64->off[i] << 2);
                            uint64_t data = datap[i];
                            int r = cb->w64(a, &addr, &data);
                            if(r == kRecfgUpdate)
                            {
                                REQ((addr & 0xfffffff000000003) == 0);
                                if(cnt == 1)
                                {
                                    w64->base = addr >> 10;
                                }
                                else
                                {
                                    REQ((addr & 0xffffffc00) == (w64->base << 10));
                                }
                                w64->off[i] = (addr >> 2) & 0xff;
                                datap[i] = data;
                                ret |= kRecfgUpdate;
                            }
                            else if(r != kRecfgSuccess)
                            {
                                retval = r;
                                goto out;
                            }
                        }
                    }
                    cmd = (recfg_cmd_t*)(datap + cnt);
                }
                break;
            default:
                goto out;
        }
    }
end:;
    retval = ret;

out:;
    return retval;
}
