/*
 * pongoOS - https://checkra.in
 *
 * Copyright (C) 2019-2023 checkra1n team
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
#ifndef DTREE_H
#define DTREE_H

#include <stdint.h>

/********** ********** ********** ********** ********** dtree.c ********** ********** ********** ********** **********/

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

int dt_check(void *mem, uint32_t size, uint32_t *offp);
int dt_parse(dt_node_t *node, int depth, uint32_t *offp, int (*cb_node)(void*, dt_node_t*), void *cbn_arg, int (*cb_prop)(void*, dt_node_t*, int, const char*, void*, uint32_t), void *cbp_arg);
dt_node_t* dt_find(dt_node_t *node, const char *name);
void* dt_prop(dt_node_t *node, const char *key, uint32_t *lenp);

/********** ********** ********** ********** ********** dtree_get.c ********** ********** ********** ********** **********/

struct memmap
{
    uint64_t addr;
    uint64_t size;
};

dt_node_t* dt_node(dt_node_t *node, const char *name);
dt_node_t* dt_get(const char *name);
void* dt_node_prop(dt_node_t *node, const char *prop, uint32_t *size);
void* dt_get_prop(const char *device, const char *prop, uint32_t *size);
uint32_t dt_node_u32(dt_node_t *node, const char *prop, uint32_t idx);
uint32_t dt_get_u32(const char *device, const char *prop, uint32_t idx);
uint64_t dt_node_u64(dt_node_t *node, const char *prop, uint32_t idx);
uint64_t dt_get_u64(const char *device, const char *prop, uint32_t idx);
struct memmap* dt_alloc_memmap(dt_node_t *node, const char *name);

uint32_t dt_get_u32_prop(const char *device, const char *prop) __attribute__((deprecated("dt_get_u32_prop is deprecated. Consider switching to dt_get_u32.", "dt_get_u32")));
uint64_t dt_get_u64_prop(const char *device, const char *prop) __attribute__((deprecated("dt_get_u64_prop is deprecated. Consider switching to dt_get_u64.", "dt_get_u64")));
uint64_t dt_get_u64_prop_i(const char *device, const char *prop, uint32_t idx) __attribute__((deprecated("dt_get_u64_prop_i is deprecated. Consider switching to dt_get_u64.", "dt_get_u64")));

#endif /* DTREE_H */
