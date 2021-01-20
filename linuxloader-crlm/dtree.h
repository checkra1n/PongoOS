/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/*
 *
 * Copyright (C) 2017-21 Corellium LLC
 * All rights reserved.
 *
 */

#ifndef _DTREE_H
#define _DTREE_H

typedef struct dt_dict_s dt_dict;

#define DT_DICT_ADD     1
#define DT_DICT_FIND    2
#define DT_DICT_ANY     3

dt_dict *dt_dict_new(int size);
void *dt_dict_find(dt_dict *dict, char *str, unsigned mode);
void dt_dict_iter(dt_dict *dict, void(*func)(void *param, char *str, void *elem), void *param);
char *dt_dict_str(void *elem);
void dt_dict_free(dt_dict *dict);

typedef struct dt_prop_s {
    void *name;
    void *buf;
    unsigned size;
    struct dt_prop_s *next;
    struct dt_node_s *parent;
} dt_prop;

typedef struct dt_node_s {
    dt_prop *prop;
    char *name;
    struct dt_node_s *child, *next, *parent;
} dt_node;

typedef struct dtree_s {
    dt_dict *names;
    dt_node *root;
    struct dt_memrsv_s {
        unsigned long base, size;
    } *memrsv;
    unsigned nmemrsv;
    unsigned bootcpuid;
} dtree;

dtree *dt_new(void);
dtree *dt_parse_dtb(void *dtb, unsigned dtblen);
unsigned dt_write_dtb(dtree *tree, void *dtb, unsigned dtbmaxlen);
dt_node *dt_find_node_idx(dtree *tree, dt_node *start, char *path, int index);
static inline dt_node *dt_find_node(dtree *tree, char *path) { return dt_find_node_idx(tree, (void *)0, path, 0); }
dt_prop *dt_find_prop(dtree *tree, dt_node *node, char *name);
dt_node *dt_add_node(dt_node *parent, char *name);
int dt_delete_node(dt_node *node);
dt_prop *dt_set_prop(dtree *tree, dt_node *node, char *name, void *buf, int size);
int dt_delete_prop(dt_prop *prop);
dt_node *dt_copy_node(dtree *tree, dt_node *parent, dt_node *source);
void dt_dump(dtree *tree);
void dt_free(dtree *tree);

unsigned dt_get32be(void *ptr);
void dt_put32be(void *ptr, unsigned val);
unsigned long dt_get64be(void *ptr);
void dt_put64be(void *ptr, unsigned long val);

#endif
