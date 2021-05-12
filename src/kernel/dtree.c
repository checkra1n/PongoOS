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
#include <pongo.h>

int dt_check(void* mem, uint32_t size, uint32_t* offp)
{
    if (size < sizeof(dt_node_t))
        return -1;
    dt_node_t* node = mem;
    uint32_t off = sizeof(dt_node_t);
    for (uint32_t i = 0, max = node->nprop; i < max; ++i) {
        if (size < off + sizeof(dt_prop_t))
            return -1;
        dt_prop_t* prop = (dt_prop_t*)((uintptr_t)mem + off);
        uint32_t l = prop->len & 0xffffff;
        off += sizeof(dt_prop_t) + ((l + 0x3) & ~0x3);
        if (size < off)
            return -1;
    }
    for (uint32_t i = 0, max = node->nchld; i < max; ++i) {
        uint32_t add = 0;
        int r = dt_check((void*)((uintptr_t)mem + off), size - off, &add);
        if (r != 0)
            return r;
        off += add;
    }
    if (offp)
        *offp = off;
    return 0;
}

int dt_parse(dt_node_t* node, int depth, uint32_t* offp, int (*cb_node)(void*, dt_node_t*), void* cbn_arg, int (*cb_prop)(void*, dt_node_t*, int, const char*, void*, uint32_t), void* cbp_arg)
{
    if (cb_node) {
        int r = cb_node(cbn_arg, node);
        if (r != 0)
            return r;
    }
    if (depth >= 0 || cb_prop) {
        uint32_t off = sizeof(dt_node_t);
        for (uint32_t i = 0, max = node->nprop; i < max; ++i) {
            dt_prop_t* prop = (dt_prop_t*)((uintptr_t)node + off);
            uint32_t l = prop->len & 0xffffff;
            off += sizeof(dt_prop_t) + ((l + 0x3) & ~0x3);
            if (cb_prop) {
                int r = cb_prop(cbp_arg, node, depth, prop->key, prop->val, l);
                if (r != 0)
                    return r;
            }
        }
        if (depth >= 0) {
            for (uint32_t i = 0, max = node->nchld; i < max; ++i) {
                uint32_t add = 0;
                int r = dt_parse((dt_node_t*)((uintptr_t)node + off), depth + 1, &add, cb_node, cbn_arg, cb_prop, cbp_arg);
                if (r != 0)
                    return r;
                off += add;
            }
            if (offp)
                *offp = off;
        }
    }
    return 0;
}

typedef struct
{
    const char *name;
    dt_node_t *node;
    int matchdepth;
} dt_find_cb_t;

static int dt_find_cb(void *a, dt_node_t *node, int depth, const char *key, void *val, uint32_t len)
{
    dt_find_cb_t *arg = a;
    if(strcmp(key, "name") != 0)
    {
        return 0;
    }
    const char *name = arg->name;
    if(name[0] == '/') // Absolute path
    {
        // If we ever get here, we traversed back out of an entry that
        // we matched against, without finding a matching child node.
        if(depth < arg->matchdepth)
        {
            return -1;
        }
        ++name;
        const char *end = strchr(name, '/');
        if(end) // Handle non-leaf segment
        {
            size_t size = end - name;
            if(strncmp(name, val, size) == 0 && size + 1 == len && ((const char*)val)[size] == '\0')
            {
                arg->name = end;
                ++arg->matchdepth;
            }
            return 0;
        }
        // Leaf segment can fall through
    }
    // Simple name
    if(strncmp(name, val, len) == 0 && strlen(name) + 1 == len)
    {
        arg->node = node;
        return 1;
    }
    return 0;
}

dt_node_t* dt_find(dt_node_t *node, const char *name)
{
    dt_find_cb_t arg = { name, NULL, 0 };
    dt_parse(node, 0, NULL, NULL, NULL, &dt_find_cb, &arg);
    return arg.node;
}

typedef struct
{
    const char *key;
    void *val;
    size_t len;
} dt_prop_cb_t;

static int dt_prop_cb(void *a, dt_node_t *node, int depth, const char *key, void *val, uint32_t len)
{
    dt_prop_cb_t *arg = a;
    if(strcmp(arg->key, key) == 0)
    {
        arg->val = val;
        arg->len = len;
        return 1;
    }
    return 0;
}

void* dt_prop(dt_node_t *node, const char *key, uint32_t *lenp)
{
    dt_prop_cb_t arg = { key, NULL, 0 };
    dt_parse(node, -1, NULL, NULL, NULL, &dt_prop_cb, &arg);
    if(arg.val && lenp) *lenp = arg.len;
    return arg.val;
}

static int dt_find_memmap_cb(void* a, dt_node_t* node, int depth, const char* key, void* val, uint32_t len)
{
    if ((key[0] == 'M' && key[1] == 'e' && key[9] == 'R' && key[10] == 'e') || (strcmp(*(void**)a, "RAMDisk") == 0)) {
        strcpy((char*)key, *(void**)a);
        *(void**)a = val;
        return 1;
    }
    return 0;
}

struct memmap* dt_alloc_memmap(dt_node_t* node, const char* name)
{
    void* val = (void*)name;
    dt_parse(node, -1, NULL, NULL, NULL, &dt_find_memmap_cb, &val);
    if (val == name)
        return NULL;
    return val;
}
