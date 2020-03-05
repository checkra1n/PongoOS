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
    uint32_t __aux[];
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
 * - RECFG_REAL_ADDR    to enable address alignment checks meant for real, life reconfig sequences
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

int recfg_check(void *mem, size_t size, size_t *offp);
int recfg_walk(void *mem, size_t size, const recfg_cb_t *cb, void *a);

#endif
