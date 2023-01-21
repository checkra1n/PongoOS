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
#include "dtree.h"
#include "pongo.h"
#include <stdint.h>
#include <string.h>

dt_node_t* dt_node(dt_node_t *node, const char *name)
{
    dt_node_t *dev = dt_find(node, name);
    if(!dev)
    {
        panic("Missing DeviceTree node: %s", name);
    }
    return dev;
}

dt_node_t* dt_get(const char *name)
{
    return dt_node(gDeviceTree, name);
}

void* dt_node_prop(dt_node_t *node, const char *prop, uint32_t *size)
{
    void *val = dt_prop(node, prop, size);
    if(!val)
    {
        panic("Missing DeviceTree prop: %s", prop);
    }
    return val;
}

void* dt_get_prop(const char *device, const char *prop, uint32_t *size)
{
    return dt_node_prop(dt_get(device), prop, size);
}

uint32_t dt_node_u32(dt_node_t *node, const char *prop, uint32_t idx)
{
    uint32_t len = 0;
    uint32_t *val = dt_node_prop(node, prop, &len);
    if(len < (idx + 1) * sizeof(*val))
    {
        panic("DeviceTree u32 out of bounds: %s[%u]", prop, idx);
    }
    return val[idx];
}

uint32_t dt_get_u32(const char *device, const char *prop, uint32_t idx)
{
    return dt_node_u32(dt_get(device), prop, idx);
}

uint64_t dt_node_u64(dt_node_t *node, const char *prop, uint32_t idx)
{
    uint32_t len = 0;
    uint64_t *val = dt_node_prop(node, prop, &len);
    if(len < (idx + 1) * sizeof(*val))
    {
        panic("DeviceTree u64 out of bounds: %s[%u]", prop, idx);
    }
    return val[idx];
}

uint64_t dt_get_u64(const char *device, const char *prop, uint32_t idx)
{
    return dt_node_u64(dt_get(device), prop, idx);
}

static int dt_alloc_memmap_cb(void *a, dt_node_t *node, int depth, const char *key, void *val, uint32_t len)
{
    if(strncmp(key, "MemoryMapReserved-", 18) != 0)
    {
        return 0;
    }
    if(len != sizeof(struct memmap))
    {
        panic("dt_alloc_memmap: property has wrong length");
    }
    strncpy((char*)key, *(void**)a, DT_KEY_LEN); // We actually want to fill the entire rest with zeroes
    *(void**)a = val;
    return 1;
}

struct memmap* dt_alloc_memmap(dt_node_t *node, const char *name)
{
    if(strlen(name) >= DT_KEY_LEN)
    {
        panic("dt_alloc_memmap: name exceeds DT_KEY_LEN");
    }
    void *val = (void*)name;
    if(dt_parse(node, -1, NULL, NULL, NULL, &dt_alloc_memmap_cb, &val) == 1)
    {
        return val;
    }
    return NULL;
}

// Legacy

uint32_t dt_get_u32_prop(const char *device, const char *prop)
{
    return dt_get_u32(device, prop, 0);
}

uint64_t dt_get_u64_prop(const char *device, const char *prop)
{
    return dt_get_u64(device, prop, 0);
}

uint64_t dt_get_u64_prop_i(const char *device, const char *prop, uint32_t idx)
{
    return dt_get_u64(device, prop, idx);
}
