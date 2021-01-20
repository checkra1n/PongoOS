/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/*
 *
 * Copyright (C) 2017-21 Corellium LLC
 * All rights reserved.
 *
 */

#include <mach-o/loader.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "dtree.h"

#define OF_DT_HEADER            0xD00DFEED
#define OF_DT_BEGIN_NODE        0x1
#define OF_DT_END_NODE          0x2
#define OF_DT_PROP              0x3
#define OF_DT_NOP               0x4
#define OF_DT_END               0x9

typedef struct dt_name_s {
    unsigned offset, refcount;
} dt_name;

dtree *dt_new(void)
{
    dtree *tree = calloc(1, sizeof(dtree));
    tree->names = dt_dict_new(sizeof(dt_name));
    if(!tree->names) {
        free(tree);
        return NULL;
    }
    return tree;
}

unsigned dt_get32be(void *ptr)
{
    unsigned char *buf = ptr;
    return ((unsigned)buf[0] << 24) | ((unsigned)buf[1] << 16) | ((unsigned)buf[2] << 8) | buf[3];
}

void dt_put32be(void *ptr, unsigned val)
{
    unsigned char *buf = ptr;
    buf[0] = val >> 24;
    buf[1] = val >> 16;
    buf[2] = val >> 8;
    buf[3] = val;
}

unsigned long dt_get64be(void *ptr)
{
    unsigned char *buf = ptr;
    return ((unsigned long)buf[0] << 56) | ((unsigned long)buf[1] << 48) | ((unsigned long)buf[2] << 40) | ((unsigned long)buf[3] << 32) |
           ((unsigned long)buf[4] << 24) | ((unsigned long)buf[5] << 16) | ((unsigned long)buf[6] << 8) | buf[7];
}

void dt_put64be(void *ptr, unsigned long val)
{
    unsigned char *buf = ptr;
    buf[0] = val >> 56;
    buf[1] = val >> 48;
    buf[2] = val >> 40;
    buf[3] = val >> 32;
    buf[4] = val >> 24;
    buf[5] = val >> 16;
    buf[6] = val >> 8;
    buf[7] = val;
}

static int dt_parse_dtb_node(unsigned char *data, unsigned datal, unsigned char *str, unsigned strl, dt_node **pnode, dt_node *parent, dt_dict *names)
{
    unsigned ptr, tkn, nptr;
    int res;
    dt_node **pchild;
    dt_prop **pprop;
    dt_name *pname;

    while(1) {
        if(datal < 8) {
            printf("[dtree] Invalid device tree binary (%d bytes left in node).\n", datal);
            return -1;
        }
        if(dt_get32be(data) == OF_DT_NOP) {
            data += 4;
            datal -= 4;
            continue;
        }
        if(dt_get32be(data) != OF_DT_BEGIN_NODE) {
            printf("[dtree] Invalid device tree binary (start node token: 0x%08X).\n", dt_get32be(data));
            return -1;
        }
        break;
    }

    ptr = 4;
    while(data[ptr]) {
        if(ptr >= datal - 4) {
            printf("[dtree] Invalid device tree binary (unterminated node name).\n");
            return -1;
        }
        ptr ++;
    }
    ptr ++;

    *pnode = calloc(1, sizeof(dt_node));
    if(!*pnode) {
        printf("[dtree] Failed to allocate node.\n");
        return -1;
    }
    (*pnode)->name = strdup((char *)data + 4);
    (*pnode)->parent = parent;
    ptr = (ptr + 3) & ~3;
    pchild = &(*pnode)->child;
    pprop = &(*pnode)->prop;

    while(1) {
        if(datal - ptr < 4) {
            printf("[dtree] Invalid device tree binary (%d bytes left in node).\n", datal - ptr);
            return -1;
        }
        tkn = dt_get32be(data + ptr);
        if(tkn == OF_DT_BEGIN_NODE) {
            res = dt_parse_dtb_node(data + ptr, datal - ptr, str, strl, pchild, *pnode, names);
            if(res < 0)
                return res;
            ptr += res;
            pchild = &(*pchild)->next;
        } else if(tkn == OF_DT_END_NODE) {
            ptr += 4;
            break;
        } else if(tkn == OF_DT_PROP) {
            if(datal - ptr < 12) {
                printf("[dtree] Invalid device tree binary (%d bytes left in property).\n", datal - ptr);
                return -1;
            }
            *pprop = calloc(1, sizeof(dt_prop));
            if(!*pprop) {
                printf("[dtree] Failed to allocate property.\n");
                return -1;
            }
            (*pprop)->parent = *pnode;
            (*pprop)->size = dt_get32be(data + ptr + 4);
            nptr = dt_get32be(data + ptr + 8);
            if(nptr >= strl || !memchr(str + nptr, 0, strl - nptr)) {
                printf("[dtree] Invalid device tree binary (property name outside string block).\n");
                return -1;
            }
            pname = dt_dict_find(names, (char *)str + nptr, DT_DICT_ANY);
            if(!pname) {
                printf("[dtree] Failed to find property name '%s' in dictionary.\n", str + nptr);
                return -1;
            }
            pname->refcount ++;
            (*pprop)->name = pname;
            if((*pprop)->size) {
                (*pprop)->buf = malloc((*pprop)->size);
                if(!(*pprop)->buf) {
                    printf("[dtree] Failed to allocate property data of size %d.\n", (*pprop)->size);
                    return -1;
                }
                memcpy((*pprop)->buf, data + ptr + 12, (*pprop)->size);
            }
            ptr += ((*pprop)->size + 15) & ~3;
            pprop = &(*pprop)->next;
        } else if(tkn == OF_DT_NOP) {
            ptr += 4;
        } else {
            printf("[dtree] Invalid device tree binary (node token: 0x%08X).\n", tkn);
            return -1;
        }
    }

    return ptr;
}

dtree *dt_parse_dtb(void *_dtb, unsigned dtblen)
{
    unsigned char *dtb = _dtb;
    dtree *tree;
    unsigned totalsize, off_struct, off_string, off_memrsv, len_struct, len_string, len_memrsv;
    unsigned i;

    if(dt_get32be(dtb) != OF_DT_HEADER) {
        printf("[dtree] Invalid device tree binary (signature: 0x%08X).\n", dt_get32be(dtb));
        return NULL;
    }

    totalsize = dt_get32be(dtb + 4);
    off_struct = dt_get32be(dtb + 8);
    off_string = dt_get32be(dtb + 12);
    off_memrsv = dt_get32be(dtb + 16);

    if(totalsize > dtblen) {
        printf("[dtree] Invalid device tree binary (length %d exceeds buffer size %d).\n", totalsize, dtblen);
        return NULL;
    }

    tree = dt_new();
    if(!tree)
        return NULL;

    len_memrsv = totalsize - off_memrsv;
    if(off_string > off_memrsv && len_memrsv > off_string - off_memrsv)
        len_memrsv = off_string - off_memrsv;
    if(off_struct > off_memrsv && len_memrsv > off_struct - off_memrsv)
        len_memrsv = off_struct - off_memrsv;

    len_struct = totalsize - off_struct;
    if(off_string > off_struct && len_struct > off_string - off_struct)
        len_struct = off_string - off_struct;
    if(off_memrsv > off_struct && len_struct > off_memrsv - off_struct)
        len_struct = off_memrsv - off_struct;

    len_string = totalsize - off_string;
    if(off_struct > off_string && len_string > off_struct - off_string)
        len_string = off_struct - off_string;
    if(off_memrsv > off_string && len_string > off_memrsv - off_string)
        len_string = off_memrsv - off_string;

    tree->bootcpuid = dt_get32be(dtb + 28);

    len_memrsv >>= 4;
    for(i=0; i<len_memrsv; i++)
        if(!dt_get64be(dtb + off_memrsv + i * 16) && !dt_get64be(dtb + off_memrsv + i * 16 + 8))
            break;
    tree->nmemrsv = i;
    if(tree->nmemrsv) {
        tree->memrsv = calloc(sizeof(struct dt_memrsv_s), tree->nmemrsv);
        if(!tree->memrsv) {
            dt_free(tree);
            return NULL;
        }
        for(i=0; i<tree->nmemrsv; i++) {
            tree->memrsv[i].base = dt_get64be(dtb + off_memrsv + i * 16);
            tree->memrsv[i].size = dt_get64be(dtb + off_memrsv + i * 16 + 8);
        }
    }

    if(dt_parse_dtb_node(dtb + off_struct, len_struct, dtb + off_string, len_string, &tree->root, NULL, tree->names) < 0) {
        dt_free(tree);
        return NULL;
    }
    return tree;
}

static void dt_write_dtb_offset_func(void *_param, char *str, void *_elem)
{
    unsigned *param = _param;
    dt_name *elem = _elem;

    if(!elem->refcount) {
        elem->offset = 0xFFFFFFFF;
        return;
    }
    elem->offset = *param;
    *param += strlen(dt_dict_str(elem)) + 1;
}

static void dt_write_dtb_write_func(void *_param, char *str, void *_elem)
{
    char *param = _param;
    dt_name *elem = _elem;

    if(elem->offset == 0xFFFFFFFF)
        return;
    strcpy(param + elem->offset, dt_dict_str(elem));
}

static int dt_write_dtb_node(dt_node *node, unsigned char *dtb, unsigned dtbmaxlen)
{
    dt_name *name;
    dt_prop *prop;
    dt_node *child;
    unsigned offset;
    int res;

    if(!node)
        return 0;

    offset = 4 + ((strlen(node->name) + 4) & ~3);
    if(dtbmaxlen < offset + 4)
        return -1;

    dt_put32be(dtb, OF_DT_BEGIN_NODE);
    strcpy((char *) dtb + 4, node->name);

    for(prop=node->prop; prop; prop=prop->next) {
        if(((prop->size + 15) & ~3) > dtbmaxlen - offset)
            return -1;
        name = prop->name;
        if(name->offset == 0xFFFFFFFF)
            return -1;
        dt_put32be(dtb + offset, OF_DT_PROP);
        dt_put32be(dtb + offset + 4, prop->size);
        dt_put32be(dtb + offset + 8, name->offset);
        if(prop->size)
            memcpy(dtb + offset + 12, prop->buf, prop->size);
        offset += (prop->size + 15) & ~3;
    }

    for(child=node->child; child; child=child->next) {
        res = dt_write_dtb_node(child, dtb + offset, dtbmaxlen - offset);
        if(res < 0)
            return res;
        offset += (res + 3) & ~3;
    }

    if(dtbmaxlen - offset < 4)
        return -1;
    dt_put32be(dtb + offset, OF_DT_END_NODE);

    return offset + 4;
}

unsigned dt_write_dtb(dtree *tree, void *_dtb, unsigned dtbmaxlen)
{
    unsigned char *dtb = _dtb;
    unsigned len_string = 0;
    int len_struct, len_memrsv, i;

    dt_dict_iter(tree->names, dt_write_dtb_offset_func, &len_string);
    len_string = (len_string + 3) & ~3;

    len_memrsv = (tree->nmemrsv + 1) * 16;

    if(dtbmaxlen < 44 + len_memrsv + len_string)
        return 0;

    len_struct = dt_write_dtb_node(tree->root, dtb + 40 + len_memrsv, dtbmaxlen - len_string - 44 - len_memrsv);
    if(len_struct < 0)
        return -1;
    dt_put32be(dtb + 40 + len_memrsv + len_struct, OF_DT_END);
    len_struct += 4;

    dt_dict_iter(tree->names, dt_write_dtb_write_func, dtb + 40 + len_memrsv + len_struct);

    for(i=0; i<tree->nmemrsv; i++) {
        dt_put64be(dtb + 40 + 16 * i, tree->memrsv[i].base);
        dt_put64be(dtb + 48 + 16 * i, tree->memrsv[i].size);
    }
    memset(dtb + 40 + 16 * tree->nmemrsv, 0, 16);

    dt_put32be(dtb, OF_DT_HEADER);
    dt_put32be(dtb + 4, 40 + len_memrsv + len_struct + len_string);
    dt_put32be(dtb + 8, 40 + len_memrsv);
    dt_put32be(dtb + 12, 40 + len_memrsv + len_struct);
    dt_put32be(dtb + 16, 40);
    dt_put32be(dtb + 20, 17); /* version */
    dt_put32be(dtb + 24, 16); /* last compatible version */
    dt_put32be(dtb + 28, tree->bootcpuid);
    dt_put32be(dtb + 32, len_string);
    dt_put32be(dtb + 36, len_struct);

    return 40 + len_memrsv + len_struct + len_string;
}

static int dt_is_string(char *str, unsigned len)
{
    unsigned cnt;
    if(len < 2)
        return 0;
    if(str[len - 1])
        return 0;
    cnt = 0;
    while(len) {
        if((*str < ' ' || *str > '~') && *str)
            return 0;
        if(*str)
            cnt ++;
        else if(!cnt)
            return 0;
        len --;
        str ++;
    }
    return 1;
}

dt_node *dt_find_node_idx(dtree *tree, dt_node *start, char *path, int index)
{
    char *sep;

    if(!tree)
        return NULL;

    if(!start || (path && path[0] == '/'))
        start = tree->root;
    if(!start)
        return NULL;

    if(!path) {
        start = start->child;
        while(start) {
            if(!index)
                return start;
            index --;
            start = start->next;
        }
        return NULL;
    }

    if(path[0] == '/')
        path ++;

    while(*path) {
        sep = strchr(path, '/');
        if(!sep)
            sep = path + strlen(path);
        start = start->child;
        while(start) {
            if(!strncmp(path, start->name, sep - path) && (!start->name[sep-path] || start->name[sep-path] == '@')) {
                if(!*sep) {
                    if(!index)
                        break;
                    index --;
                } else
                    break;
            }
            start = start->next;
        }
        if(!start)
            return NULL;
        path = *sep ? sep + 1 : sep;
    }
    return start;
}

dt_prop *dt_find_prop(dtree *tree, dt_node *node, char *name)
{
    void *key;
    dt_prop *prop;
    if(!tree || !node)
        return NULL;

    key = dt_dict_find(tree->names, name, DT_DICT_FIND);
    if(!key)
        return NULL;

    for(prop=node->prop; prop; prop=prop->next)
        if(prop->name == key)
            break;
    return prop;
}

dt_node *dt_add_node(dt_node *parent, char *name)
{
    dt_node *node = calloc(1, sizeof(dt_node)), **pnode;
    if(!node)
        return NULL;

    node->name = strdup(name);
    node->parent = parent;
    for(pnode=&parent->child; *pnode; pnode=&(*pnode)->next) ;
    *pnode = node;
    return node;
}

int dt_delete_node(dt_node *node)
{
    dt_node **pnode;
    dt_prop *prop;
    if(!node->parent)
        return 1;

    for(pnode=&node->parent->child; *pnode; pnode=&(*pnode)->next)
        if(*pnode == node)
            break;
    if(!*pnode)
        return 1;

    while(node->child)
        if(dt_delete_node(node->child))
            return 1;

    while(node->prop) {
        prop = node->prop;
        node->prop = prop->next;
        ((dt_name *)prop->name)->refcount --;
        free(prop->buf);
        free(prop);
    }

    *pnode = node->next;
    free(node);
    return 0;
}

dt_prop *dt_set_prop(dtree *tree, dt_node *node, char *name, void *buf, int size)
{
    dt_name *key = dt_dict_find(tree->names, name, DT_DICT_ANY);
    dt_prop **pprop;
    void *nbuf;
    if(!key)
        return NULL;

    if(size < 0 && buf)
        size = strlen(buf) + 1;

    for(pprop=&node->prop; *pprop; pprop=&(*pprop)->next)
        if((*pprop)->name == key)
            break;
    if(!*pprop) {
        *pprop = calloc(1, sizeof(dt_prop));
        (*pprop)->parent = node;
        (*pprop)->name = key;
        key->refcount ++;
    }

    if((*pprop)->size >= size) {
        if(buf)
            memcpy((*pprop)->buf, buf, size);
        (*pprop)->size = size;
    } else {
        nbuf = malloc(size);
        if(!nbuf)
            return NULL;
        free((*pprop)->buf);
        if(buf)
            memcpy(nbuf, buf, size);
        (*pprop)->buf = nbuf;
        (*pprop)->size = size;
    }

    return *pprop;
}

int dt_delete_prop(dt_prop *prop)
{
    dt_prop **pprop;

    for(pprop=&prop->parent->prop; *pprop; pprop=&(*pprop)->next)
        if(*pprop == prop)
            break;
    if(!*pprop)
        return 1;

    ((dt_name *)prop->name)->refcount --;
    free(prop->buf);

    *pprop = prop->next;
    free(prop);
    return 0;
}

dt_node *dt_copy_node(dtree *tree, dt_node *parent, dt_node *source)
{
    dt_node **pnode, *iter;
    dt_prop *prop;

    if(!parent || !source)
        return NULL;

    for(pnode=&parent->child; *pnode; pnode=&(*pnode)->next)
        if(!strcmp((*pnode)->name, source->name))
            break;
    if(!*pnode) {
        *pnode = calloc(1, sizeof(dt_node));
        if(!*pnode)
            return NULL;
        (*pnode)->name = strdup(source->name);
        (*pnode)->parent = parent;
    }

    for(iter=source->child; iter; iter=iter->next)
        if(!dt_copy_node(tree, *pnode, iter))
            return NULL;

    for(prop=source->prop; prop; prop=prop->next)
        if(!dt_set_prop(tree, *pnode, dt_dict_str(prop->name), prop->buf, prop->size))
            return NULL;

    return *pnode;
}

static void dt_dump_node(dt_node *node, unsigned indent)
{
    dt_node *child;
    dt_prop *prop;
    unsigned i, v;

    printf("%*s%s {\n", indent, "", node->name[0] ? node->name : "/");
    for(prop=node->prop; prop; prop=prop->next) {
        printf("%*s%s", indent + 2, "", dt_dict_str(prop->name));
        if(prop->size) {
            printf(" = ");
            if(!dt_is_string(prop->buf, prop->size)) {
                if(prop->size & 3) {
                    printf("[");
                    for(i=0; i<prop->size; i++)
                        printf(" %02x", ((unsigned char *)prop->buf)[i]);
                    printf(" ]");
                } else {
                    for(i=0; i<prop->size/4; i++) {
                        v = dt_get32be(((unsigned char *)prop->buf) + i * 4);
                        printf(v >= 16 ? "%s0x%x" : "%s%d", i ? ", " : "", v);
                    }
                }
            } else
                for(i=0; i<prop->size; i+=strlen(prop->buf+i)+1)
                    printf("%s\"%s\"", i ? ", " : "", (char *) prop->buf + i);
        }
        printf("\n");
    }
    for(child=node->child; child; child=child->next)
        dt_dump_node(child, indent + 2);
    printf("%*s}\n", indent, "");
}

void dt_dump(dtree *tree)
{
    unsigned i;
    for(i=0; i<tree->nmemrsv; i++)
        printf("/memreserve/ 0x%lx 0x%lx;\n", tree->memrsv[i].base, tree->memrsv[i].size);
    dt_dump_node(tree->root, 0);
}

static void dt_free_node(dt_node *node)
{
    dt_node *child;
    dt_prop *prop;

    while(node->child) {
        child = node->child;
        node->child = child->next;
        dt_free_node(child);
    }
    while(node->prop) {
        prop = node->prop;
        node->prop = prop->next;
        free(prop->buf);
        free(prop);
    }

    free(node->name);
    free(node);
}

void dt_free(dtree *tree)
{
    dt_free_node(tree->root);
    dt_dict_free(tree->names);
    free(tree);
}
