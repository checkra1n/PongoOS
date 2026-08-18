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
#include "dt.h"
#include "pongo.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// ========== DT ==========

int dt_check(void *mem, size_t size, size_t *offp)
{
    if(size < sizeof(dt_node_t)) return -1;
    dt_node_t *node = mem;
    size_t off = sizeof(dt_node_t);
    for(size_t i = 0, max = node->nprop; i < max; ++i)
    {
        if(size < off + sizeof(dt_prop_t)) return -1;
        dt_prop_t *prop = (dt_prop_t*)((uintptr_t)mem + off);
        size_t l = prop->len & 0xffffff;
        off += sizeof(dt_prop_t) + ((l + 0x3) & ~0x3);
        if(size < off) return -1;
    }
    for(size_t i = 0, max = node->nchld; i < max; ++i)
    {
        size_t add = 0;
        int r = dt_check((void*)((uintptr_t)mem + off), size - off, &add);
        if(r != 0) return r;
        off += add;
    }
    if(offp) *offp = off;
    return 0;
}

int dt_parse(dt_node_t *node, int depth, size_t *offp, int (*cb_node)(void*, dt_node_t*, int), void *cbn_arg, int (*cb_prop)(void*, dt_node_t*, int, const char*, void*, size_t), void *cbp_arg)
{
    if(cb_node)
    {
        int r = cb_node(cbn_arg, node, depth);
        if(r != 0) return r;
    }
    if(depth >= 0 || cb_prop)
    {
        size_t off = sizeof(dt_node_t);
        for(size_t i = 0, max = node->nprop; i < max; ++i)
        {
            dt_prop_t *prop = (dt_prop_t*)((uintptr_t)node + off);
            size_t l = prop->len & 0xffffff;
            off += sizeof(dt_prop_t) + ((l + 0x3) & ~0x3);
            if(cb_prop)
            {
                int r = cb_prop(cbp_arg, node, depth, prop->key, prop->val, l);
                if(r != 0) return r;
            }
        }
        if(depth >= 0)
        {
            for(size_t i = 0, max = node->nchld; i < max; ++i)
            {
                size_t add = 0;
                int r = dt_parse((dt_node_t*)((uintptr_t)node + off), depth + 1, &add, cb_node, cbn_arg, cb_prop, cbp_arg);
                if(r != 0) return r;
                off += add;
            }
            if(offp) *offp = off;
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

static int dt_find_cb(void *a, dt_node_t *node, int depth, const char *key, void *val, size_t len)
{
    dt_find_cb_t *arg = a;
    if(strcmp(key, "name") != 0)
    {
        return 0;
    }
    const char *name = arg->name;
    if(name[0] == '/') // Absolute path
    {
        // Don't require "/device-tree" prefix for everything.
        if(depth == 0)
        {
            return 0;
        }
        // If we're in the subtree of a node we didn't match against, then ignore everything.
        if(depth > arg->matchdepth)
        {
            return 0;
        }
        // If this condition is ever true, then we traversed back out of an entry
        // that we matched against, without finding a matching child node.
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
                arg->matchdepth = depth + 1;
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
    dt_find_cb_t arg = { name, NULL, 1 };
    dt_parse(node, 0, NULL, NULL, NULL, &dt_find_cb, &arg);
    return arg.node;
}

typedef struct
{
    const char *key;
    void *val;
    size_t len;
} dt_prop_cb_t;

static int dt_prop_cb(void *a, dt_node_t *node, int depth, const char *key, void *val, size_t len)
{
    dt_prop_cb_t *arg = a;
    if(strncmp(arg->key, key, DT_KEY_LEN) == 0)
    {
        arg->val = val;
        arg->len = len;
        return 1;
    }
    return 0;
}

void* dt_prop(dt_node_t *node, const char *key, size_t *lenp)
{
    dt_prop_cb_t arg = { key, NULL, 0 };
    dt_parse(node, -1, NULL, NULL, NULL, &dt_prop_cb, &arg);
    if(arg.val && lenp) *lenp = arg.len;
    return arg.val;
}

// ========== CLI ==========

#define LOG(str, args...) do { iprintf(str "\n", ##args); } while(0)
#define ERR LOG
#define REQ(expr) do { panic("!(" #expr ")"); } while(0)

typedef struct
{
    const char *name;
    const char *prop;
    size_t size;
} dt_arg_t;

static int dt_cbn(void *a, dt_node_t *node, int depth)
{
    if(a != node)
    {
        LOG("--------------------------------------------------------------------------------------------------------------------------------");
    }
    return 0;
}

static int dt_cbp(void *a, dt_node_t *node, int depth, const char *key, void *val, size_t len)
{
    int retval = 0;
    dt_arg_t *arg = a;
    const char *prop = arg->prop;
    if(!prop || strncmp(prop, key, DT_KEY_LEN) == 0)
    {
        // Print name, if we're in single-prop mode and recursive
        if(depth >= 0 && prop && strcmp(key, "name") != 0)
        {
            size_t l = 0;
            void *v = dt_prop(node, "name", &l);
            if(v)
            {
                dt_arg_t tmp = *arg;
                tmp.prop = NULL;
                retval = dt_cbp(&tmp, node, depth, "name", v, l);
            }
        }
        if(depth < 0) depth = 0;
        bool printable = true, visible = false;
        char *str = val;
        for(size_t i = 0; i < len; ++i)
        {
            char c = str[i];
            if(c == 0x0 && i == len - 1)
            {
                continue;
            }
            if((c < 0x20 || c >= 0x7f) && c != '\t' && c != '\n')
            {
                printable = false;
                break;
            }
            if(c != ' ' && c != '\t' && c != '\n')
            {
                visible = true;
            }
        }
        if(len == 0)
        {
            LOG("%*s%-*s %-*s  ||", depth * 4, "", DT_KEY_LEN, key, 49, "");
        }
        else if(printable && visible)
        {
            LOG("%*s%-*s %.*s", depth * 4, "", DT_KEY_LEN, key, (int)len, str);
        }
        else if(len == 1 || len == 2 || len == 4) // 8 is usually not uint64
        {
            uint64_t v = 0;
            for(size_t i = 0; i < len; ++i)
            {
                uint8_t c = str[i];
                v |= (uint64_t)c << (i * 8);
            }
            LOG("%*s%-*s 0x%0*llx", depth * 4, "", DT_KEY_LEN, key, (int)len * 2, v);
        }
        else
        {
            const char *k = key;
            const char *hex = "0123456789abcdef";
            char xs[49] = {};
            char cs[17] = {};
            size_t sz = arg->size;
            if(sz == 8)
            {
                xs[0]  = xs[19] = '0';
                xs[1]  = xs[20] = 'x';
                xs[18] = xs[37] = ' ';
            }
            else if(sz == 4)
            {
                xs[0]  = xs[11] =          xs[23] = xs[34] = '0';
                xs[1]  = xs[12] =          xs[24] = xs[35] = 'x';
                xs[10] = xs[21] = xs[22] = xs[33] = xs[44] = ' ';
            }
            else
            {
                xs[2] = xs[5] = xs[8] = xs[11] = xs[14] = xs[17] = xs[20] = xs[23] = xs[24] = xs[27] = xs[30] = xs[33] = xs[36] = xs[39] = xs[42] = xs[45] = ' ';
            }
            size_t i;
            for(i = 0; i < len; ++i)
            {
                uint8_t c = str[i];
                size_t is = i % 0x10;
                size_t ix;
                if(sz == 8)
                {
                    ix = (is >= 0x8 ? 51 : 16) - (2 * is);
                }
                else if(sz == 4)
                {
                    ix = (is >= 0x8 ? (is >= 0xc ? 66 : 47) : (is >= 0x4 ? 27 : 8)) - (2 * is);
                }
                else
                {
                    ix = 3 * is + (is >= 0x8 ? 1 : 0);
                }
                xs[ix    ] = hex[(c >> 4) & 0xf];
                xs[ix + 1] = hex[(c     ) & 0xf];
                cs[is] = c >= 0x20 && c < 0x7f ? c : '.';
                if(is == 0xf)
                {
                    LOG("%*s%-*s %-*s  |%s|", depth * 4, "", DT_KEY_LEN, k, (int)sizeof(xs), xs, cs);
                    k = "";
                }
            }
            if((i % 0x10) != 0)
            {
                size_t is = i % 0x10;
                size_t ix;
                // If we only have a single int, pull it back so it doesn't look odd.
                if(len < sz)
                {
                    size_t off = 2 * (sz - len);
                    for(ix = 2; ix < 2 * len + 2; ++ix)
                    {
                        xs[ix] = xs[ix + off];
                    }
                }
                else if(sz == 8)
                {
                    ix = (is >= 0x8 ? 51 : 16) - (2 * is);
                    xs[ix    ] = '0';
                    xs[ix + 1] = 'x';
                    for(size_t iz = is >= 0x8 ? 19 : 0; iz < ix; ++iz)
                    {
                        xs[iz] = ' ';
                    }
                    ix = is > 0x8 ? 37 : 18;
                }
                else if(sz == 4)
                {
                    ix = (is >= 0x8 ? (is >= 0xc ? 66 : 47) : (is >= 0x4 ? 27 : 8)) - (2 * is);
                    xs[ix    ] = '0';
                    xs[ix + 1] = 'x';
                    for(size_t iz = is >= 0x8 ? (is >= 0xc ? 34 : 23) : (is >= 0x4 ? 11 : 0); iz < ix; ++iz)
                    {
                        xs[iz] = ' ';
                    }
                    ix = is > 0x8 ? (is > 0xc ? 44 : 33) : (is > 0x4 ? 21 : 10);
                }
                else
                {
                    ix = 3 * is + (is >= 0x8 ? 1 : 0);
                }
                xs[ix] = '\0';
                cs[is] = '\0';
                LOG("%*s%-*s %-*s  |%s|", depth * 4, "", DT_KEY_LEN, k, (int)sizeof(xs), xs, cs);
            }
        }
    }
    return retval;
}

static int dt(dt_node_t *mem, dt_arg_t *arg)
{
    int retval = -1;
    char *str = NULL;

    const char *name = NULL;
    bool recurse = true;
    if(arg->name)
    {
        const char *slash = strrchr(arg->name, '/');
        if(slash && slash[1] == '\0')
        {
            str = strndup(arg->name, slash - arg->name);
            REQ(str);
            name = str;
        }
        else
        {
            name = arg->name;
            recurse = false;
        }
    }

    dt_node_t *node = (name && name[0]) ? dt_find(mem, name) : mem;
    if(!node)
    {
        LOG("Failed to find node");
        goto out;
    }

    retval = dt_parse(node, recurse ? 0 : -1, NULL, recurse ? &dt_cbn : NULL, node, &dt_cbp, arg);
out:;
    if(str) free(str);
    return retval;
}

int dt_print(dt_node_t *node, int argc, const char **argv)
{
    size_t size = 0;
    if(argc > 0 && argv[argc-1][0] == '-')
    {
        --argc;
        if(argv[argc][1] == '4' && argv[argc][2] == '\0')
        {
            size = 4;
        }
        else if(argv[argc][1] == '8' && argv[argc][2] == '\0')
        {
            size = 8;
        }
        else
        {
            ERR("Bad flag: %s", argv[argc]);
            return -1;
        }
    }
    dt_arg_t arg =
    {
        .name = argc > 0 ? argv[0] : NULL,
        .prop = argc > 1 ? argv[1] : NULL,
        .size = size,
    };
    return dt(node, &arg);
}

// ========== Legacy/Compat ==========

int dt_check_32(void *mem, uint32_t size, uint32_t *offp) __asm__("_dt_check$32");
int dt_parse_32(dt_node_t *node, int depth, uint32_t *offp, int (*cb_node)(void*, dt_node_t*, int), void *cbn_arg, int (*cb_prop)(void*, dt_node_t*, int, const char*, void*, uint32_t), void *cbp_arg) __asm__("_dt_parse$32");
void* dt_prop_32(dt_node_t *node, const char *key, uint32_t *lenp) __asm__("_dt_prop$32");

int dt_check_32(void *mem, uint32_t size, uint32_t *offp)
{
    size_t off = 0;
    int r = dt_check(mem, size, &off);
    if(offp) *offp = (uint32_t)off;
    return r;
}

typedef struct
{
    int (*cb)(void *a, dt_node_t *node, int depth, const char *key, void *val, uint32_t len);
    void *arg;
} dt_parse_32_cbp_t;

static int dt_parse_32_cbp(void *a, dt_node_t *node, int depth, const char *key, void *val, size_t len)
{
    dt_parse_32_cbp_t *args = a;
    return args->cb(args->arg, node, depth, key, val, (uint32_t)len);
}

int dt_parse_32(dt_node_t *node, int depth, uint32_t *offp, int (*cb_node)(void*, dt_node_t*, int), void *cbn_arg, int (*cb_prop)(void*, dt_node_t*, int, const char*, void*, uint32_t), void *cbp_arg)
{
    dt_parse_32_cbp_t cbp_arg_32 =
    {
        .cb  = cb_prop,
        .arg = cbp_arg,
    };
    int (*cb_prop_32)(void*, dt_node_t*, int, const char*, void*, size_t) = dt_parse_32_cbp;
    cbp_arg = &cbp_arg_32;
    if(!cb_prop)
    {
        cb_prop_32 = NULL;
        cbp_arg = NULL;
    }
    size_t off = 0;
    int r = dt_parse(node, depth, &off, cb_node, cbn_arg, cb_prop_32, cbp_arg);
    if(offp) *offp = (uint32_t)off;
    return r;
}

void* dt_prop_32(dt_node_t *node, const char *key, uint32_t *lenp)
{
    size_t len = 0;
    void *val = dt_prop(node, key, &len);
    if(lenp) *lenp = (uint32_t)len;
    return val;
}
