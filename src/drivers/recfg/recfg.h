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

#ifndef RECFG_H
#define RECFG_H

#include <stdbool.h>
#include <stddef.h>             // size_t
#include <stdint.h>

enum
{
    kRecfgFailure   = -1,
    kRecfgSuccess   =  0,
    kRecfgUpdate    =  1,
    // reserved up to 15
};

enum
{
    kRecfgMeta      = 0,
    kRecfgWrite32   = 1,
    kRecfgRead      = 2,
    kRecfgWrite64   = 3,
};

enum
{
    kRecfgEnd       = 0,
    kRecfgDelay     = 1,
};

#ifdef RECFG_VOLATILE

// For use on actual MMIO / uncached memory with alignment restrictions.
// Refer to the #else case for readable definitions.

typedef struct { volatile uint32_t a;                } recfg_cmd_t, recfg_read_t, recfg_write32_t, recfg_write64_t;
typedef struct { volatile uint32_t a, b, mask, data; } recfg_read32_t;
typedef struct { volatile uint32_t a, b;             } recfg_read64_t;

#define RECFG_CMD_CMD_r(_cmd)           (_cmd->a & 0x3)
#define RECFG_CMD_META_r(_cmd)         ((_cmd->a >> 2) & 0xf)
#define RECFG_CMD_DATA_r(_cmd)         ((_cmd->a >> 6) & 0x3ffffff)
#define RECFG_CMD_DATA_w(_cmd, _v)      (_cmd->a = (_cmd->a & 0x3f) | (((_v) << 6) & 0xffffffc0))

#define RECFG_READ_COUNT_r(_cmd)       ((_cmd->a >> 2) & 0x7)
#define RECFG_READ_LARGE_r(_cmd)       ((_cmd->a >> 5) & 0x1)
#define RECFG_READ_BASE_r(_cmd)         RECFG_CMD_DATA_r(_cmd)
#define RECFG_READ_BASE_w(_cmd, _v)     RECFG_CMD_DATA_w(_cmd, _v)
#define RECFG_READ_OFF_r(_cmd)          (_cmd->b & 0xff)
#define RECFG_READ_OFF_w(_cmd, _v)      (_cmd->b = (_cmd->b & 0xffffff00) | ((_v) & 0xff))
#define RECFG_READ_RECNT_r(_cmd)       ((_cmd->b >> 8) & 0xff)
#define RECFG_READ_RECNT_w(_cmd, _v)    (_cmd->b = (_cmd->b & 0xffff00ff) | (((_v) << 8) & 0xff00))
#define RECFG_READ_RETRY_r(_cmd)       ((_cmd->b >> 16) & 0x1)
#define RECFG_READ_RETRY_w(_cmd, _v)    (_cmd->b = (_cmd->b & 0xfffeffff) | (((_v) << 16) & 0x10000))

#define RECFG_WRITE_COUNT_r(_cmd)      ((_cmd->a >> 2) & 0xf)
#define RECFG_WRITE_BASE_r(_cmd)        RECFG_CMD_DATA_r(_cmd)
#define RECFG_WRITE_BASE_w(_cmd, _v)    RECFG_CMD_DATA_w(_cmd, _v)
#define RECFG_WRITE_OFF_r(_cmd, _i)    ((((volatile uint32_t*)(_cmd + 1))[(_i) / 4] >> (((_i) & 0x3) * 8)) & 0xff)
#define RECFG_WRITE_OFF_w(_cmd, _i, _v) (((volatile uint32_t*)(_cmd + 1))[(_i) / 4] = (((volatile uint32_t*)(_cmd + 1))[(_i) / 4] & ~(0xff << (((_i) & 0x3) * 8))) | ((_v) & (0xff << (((_i) & 0x3) * 8))))

#else

typedef struct
{
    uint32_t cmd   :  2,
             meta  :  4,
             data  : 26;
} __attribute__((packed)) recfg_cmd_t;

typedef struct
{
    uint32_t cmd   :  2,
             count :  3,
             large :  1,
             base  : 26;
} __attribute__((packed)) recfg_read_t;

typedef struct
{
    uint32_t cmd   :  2,
             count :  3,
             large :  1,
             base  : 26;
    uint32_t off   :  8,
             recnt :  8,
             retry :  1,
             __res : 15;
    uint32_t mask;
    uint32_t data;
} __attribute__((packed)) recfg_read32_t;

typedef struct
{
    uint32_t cmd   :  2,
             count :  3,
             large :  1,
             base  : 26;
    uint32_t off   :  8,
             recnt :  8,
             retry :  1,
             __res : 15;
    // uint64_t mask;
    // uint64_t data;
} __attribute__((packed)) recfg_read64_t;

typedef struct
{
    uint32_t cmd   :  2,
             count :  4,
             base  : 26;
    uint8_t  off[];
    // uint32_t data[];
} __attribute__((packed)) recfg_write32_t;

typedef struct
{
    uint32_t cmd   :  2,
             count :  4,
             base  : 26;
    uint8_t  off[];
    // uint64_t data[];
} __attribute__((packed)) recfg_write64_t;

#define RECFG_CMD_CMD_r(_cmd)           (_cmd->cmd)
#define RECFG_CMD_META_r(_cmd)          (_cmd->meta)
#define RECFG_CMD_DATA_r(_cmd)          (_cmd->data)
#define RECFG_CMD_DATA_w(_cmd, _v)      (_cmd->data = (_v))

#define RECFG_READ_COUNT_r(_cmd)        (_cmd->count)
#define RECFG_READ_LARGE_r(_cmd)        (_cmd->large)
#define RECFG_READ_BASE_r(_cmd)         (_cmd->base)
#define RECFG_READ_BASE_w(_cmd, _v)     (_cmd->base = (_v))
#define RECFG_READ_OFF_r(_cmd)          (_cmd->off)
#define RECFG_READ_OFF_w(_cmd, _v)      (_cmd->off = (_v))
#define RECFG_READ_RECNT_r(_cmd)        (_cmd->recnt)
#define RECFG_READ_RECNT_w(_cmd, _v)    (_cmd->recnt = (_v))
#define RECFG_READ_RETRY_r(_cmd)        (_cmd->retry)
#define RECFG_READ_RETRY_w(_cmd, _v)    (_cmd->retry = (_v))

#define RECFG_WRITE_COUNT_r(_cmd)       (_cmd->count)
#define RECFG_WRITE_BASE_r(_cmd)        (_cmd->base)
#define RECFG_WRITE_BASE_w(_cmd, _v)    (_cmd->base = (_v))
#define RECFG_WRITE_OFF_r(_cmd, _i)     (_cmd->off[_i])
#define RECFG_WRITE_OFF_w(_cmd, _i, _v) (_cmd->off[_i] = (_v))

#endif

typedef int (*recfg_generic_cb_t)(void *a, const recfg_cmd_t *cmd);
typedef int (*recfg_end_cb_t)(void *a);
typedef int (*recfg_delay_cb_t)(void *a, uint32_t *delay);
typedef int (*recfg_read32_cb_t)(void *a, uint64_t *addr, uint32_t *mask, uint32_t *data, bool *retry, uint8_t *recnt);
typedef int (*recfg_read64_cb_t)(void *a, uint64_t *addr, uint64_t *mask, uint64_t *data, bool *retry, uint8_t *recnt);
typedef int (*recfg_write32_cb_t)(void *a, uint64_t *addr, uint32_t *data);
typedef int (*recfg_write64_cb_t)(void *a, uint64_t *addr, uint64_t *data);

typedef struct
{
    recfg_generic_cb_t generic;
    recfg_end_cb_t end;
    recfg_delay_cb_t delay;
    recfg_read32_cb_t r32;
    recfg_read64_cb_t r64;
    recfg_write32_cb_t w32;
    recfg_write64_cb_t w64;
} recfg_cb_t;

/**
 * API doc
 *
 * When using this as a library, define the following macros:
 * - RECFG_IO           to enable error logging to stderr
 * - ERR(str, args...)  to enable error logging to a custom facility
 *                      you have access to a `const bool warn` variable
 * - RECFG_VOLATILE     to enable address alignment checks meant for real, live reconfig sequences
 *
 * `mem` and `size` should be pointer to and length of the reconfig sequence.
 *
 *
 * recfg_check()
 *
 * You must first call recfg_check(), which will sanity-check the script.
 * If this does not return kRecfgSuccess, do not proceed!
 * If `offp` is non-NULL, it will be set to:
 * - on success, a pointer to the uint32 after the end of the sequence.
 * - on failure, to the start of the command that failed the sanity check.
 * The `warn` argument will be made available to the ERR macro.
 *
 *
 * recfg_walk()
 *
 * After that, you can call recfg_walk() with a set of callbacks and an opaque argument.
 * Any callback that is non-NULL will be invoked for every operation it corresponds to,
 * and the opaque pointer will be passed to it as first arg.
 * The `generic` callback will be called for every command.
 *
 * Except for `generic`, callbacks are free to modify the values at the pointers passed to it, however:
 * - They must return `kRecfgUpdate` if they choose to do so, otherwise the changes will be lost.
 * - `addr` must not exceed 36 bits, and must be 4-byte aligned.
 * - If writes are batched, the new value of `addr` must fall within the same 1KB block as the old one.
 *
 * The `generic` callback is NOT allowed to modify the command passed to it, but is intended for use
 * when the other callbacks are not powerful enough for your needs (e.g. inserting or deleting commands).
 * In such cases, it is recommended that you do not modify the original sequence at all, but use the
 * opaque pointer to build your own sequence based on the commands passed to the `generic` callback.
 *
 * If any callback returns a value other than `kRecfgSuccess` or `kRecfgUpdate`,
 * parsing will stop and the returned value will be passed back to the caller.
 * If any of the callbacks returned `kRecfgUpdate`, recfg_walk() will also do that,
 * and in that case you are responsible for writing `mem` back to where it came from, if applicable.
**/

int recfg_check(void *mem, size_t size, size_t *offp, const bool warn);
int recfg_walk(void *mem, size_t size, const recfg_cb_t *cb, void *a);

#endif
