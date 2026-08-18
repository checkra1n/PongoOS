/*
 * pongoOS - https://checkra.in
 *
 * Copyright (C) 2019-2024 checkra1n team
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
#ifndef DT_H
#define DT_H

#include <stddef.h>
#include <stdint.h>

/********** ********** ********** ********** ********** dt.c ********** ********** ********** ********** **********/

#define DT_KEY_LEN 0x20

typedef struct
{
    uint32_t nprop;
    uint32_t nchld;
    char prop[];
} dt_node_t;

typedef struct
{
    char key[DT_KEY_LEN];
    uint32_t len;
    char val[];
} dt_prop_t;

extern int dt_check(void *mem, size_t size, size_t *offp) __asm__("_dt_check$64");
extern int dt_parse(dt_node_t *node, int depth, size_t *offp, int (*cb_node)(void*, dt_node_t*, int), void *cbn_arg, int (*cb_prop)(void*, dt_node_t*, int, const char*, void*, size_t), void *cbp_arg) __asm__("_dt_parse$64");
extern dt_node_t* dt_find(dt_node_t *node, const char *name);
extern void* dt_prop(dt_node_t *node, const char *key, size_t *lenp) __asm__("_dt_prop$64");
extern int dt_print(dt_node_t *node, int argc, const char **argv);

/********** ********** ********** ********** ********** dt_get.c ********** ********** ********** ********** **********/

extern dt_node_t *gDeviceTree;

struct memmap
{
    uint64_t addr;
    uint64_t size;
};

extern dt_node_t* dt_node(dt_node_t *node, const char *name);
extern dt_node_t* dt_node_parent(dt_node_t *node);
extern dt_node_t* dt_get(const char *name);
extern void* dt_node_prop(dt_node_t *node, const char *prop, size_t *size);
extern void* dt_get_prop(const char *device, const char *prop, size_t *size) __asm__("_dt_get_prop$64");
extern uint32_t dt_node_u32(dt_node_t *node, const char *prop, uint32_t idx);
extern uint32_t dt_get_u32(const char *device, const char *prop, uint32_t idx);
extern uint64_t dt_node_u64(dt_node_t *node, const char *prop, uint32_t idx);
extern uint64_t dt_get_u64(const char *device, const char *prop, uint32_t idx);
extern struct memmap* dt_alloc_memmap(dt_node_t *node, const char *name);

extern uint32_t dt_get_u32_prop(const char *device, const char *prop) __attribute__((deprecated("dt_get_u32_prop is deprecated. Consider switching to dt_get_u32.", "dt_get_u32")));
extern uint64_t dt_get_u64_prop(const char *device, const char *prop) __attribute__((deprecated("dt_get_u64_prop is deprecated. Consider switching to dt_get_u64.", "dt_get_u64")));
extern uint64_t dt_get_u64_prop_i(const char *device, const char *prop, uint32_t idx) __attribute__((deprecated("dt_get_u64_prop_i is deprecated. Consider switching to dt_get_u64.", "dt_get_u64")));

#endif /* DT_H */
