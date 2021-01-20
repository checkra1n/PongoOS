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

typedef struct dt_elem_s {
    unsigned depth;
    struct dt_elem_s *left, *right, *parent, **up;
    char *str;
} dt_elem;

struct dt_dict_s {
    int size;
    dt_elem *root;
};

dt_dict *dt_dict_new(int size)
{
    dt_dict *dict = calloc(1, sizeof(dt_dict));
    if(!dict)
        return dict;
    dict->size = size;
    return dict;
}

static int dt_dict_delta(dt_elem *elem)
{
    int res = 0;
    if(elem->left)
        res -= elem->left->depth + 1;
    if(elem->right)
        res += elem->right->depth + 1;
    return res;
}

static void dt_dict_update(dt_elem *elem)
{
    elem->depth = 0;
    if(elem->left)
        elem->depth = elem->left->depth + 1;
    if(elem->right && elem->depth < elem->right->depth + 1)
        elem->depth = elem->right->depth + 1;
}

static void dt_dict_pivot(dt_elem *root, dt_elem *pivot)
{
    pivot->parent = root->parent;
    pivot->up = root->up;
    *(pivot->up) = pivot;

    if(pivot == root->left) {
        root->left = pivot->right;
        if(root->left) {
            root->left->parent = root;
            root->left->up = &(root->left);
        }

        root->parent = pivot;
        root->up = &(pivot->right);
        pivot->right = root;
    } else {
        root->right = pivot->left;
        if(root->right) {
            root->right->parent = root;
            root->right->up = &(root->right);
        }

        root->parent = pivot;
        root->up = &(pivot->left);
        pivot->left = root;
    }

    dt_dict_update(root);
    dt_dict_update(pivot);
}

static void dt_dict_rebalance(dt_elem *elem)
{
    int delta;

    dt_dict_update(elem);

    for(; elem; elem=elem->parent) {
        delta = dt_dict_delta(elem);
        if(delta < -1 || delta > 1) {
            if(delta < -2 || delta > 2)
                return;

            if(delta < -1) {
                if(dt_dict_delta(elem->left) > 0)
                    dt_dict_pivot(elem->left, elem->left->right);
                dt_dict_pivot(elem, elem->left);
            } else {
                if(dt_dict_delta(elem->right) < 0)
                    dt_dict_pivot(elem->right, elem->right->left);
                dt_dict_pivot(elem, elem->right);
            }
            elem = elem->parent;
        }

        if(!elem || !elem->parent)
            break;

        dt_dict_update(elem->parent);
    }
}

void *dt_dict_find(dt_dict *_dict, char *str, unsigned mode)
{
    dt_dict *dict = _dict;
    dt_elem **pelem = &(dict->root), *parent = NULL;
    int cmp;

    while(*pelem) {
        cmp = strcmp(str, (*pelem)->str);
        if(!cmp) {
            if(!(mode & DT_DICT_FIND))
                return NULL;
            return (*pelem) + 1;
        }

        parent = *pelem;
        if(cmp < 0)
            pelem = &(*pelem)->left;
        else
            pelem = &(*pelem)->right;
    }

    if(!(mode & DT_DICT_ADD))
        return NULL;

    (*pelem) = calloc(1, sizeof(dt_elem) + dict->size);
    if(!*pelem)
        return NULL;

    (*pelem)->str = strdup(str);
    (*pelem)->up = pelem;
    (*pelem)->parent = parent;

    parent = *pelem;
    dt_dict_rebalance(*pelem);

    return parent + 1;
}

static void dt_dict_iter_recurse(dt_elem *elem, void(*func)(void *param, char *str, void *elem), void *param)
{
    if(elem->left)
        dt_dict_iter_recurse(elem->left, func, param);
    func(param, elem->str, elem + 1);
    if(elem->right)
        dt_dict_iter_recurse(elem->right, func, param);
}

void dt_dict_iter(dt_dict *_dict, void(*func)(void *param, char *str, void *elem), void *param)
{
    dt_dict *dict = _dict;
    if(dict->root)
        dt_dict_iter_recurse(dict->root, func, param);
}

char *dt_dict_str(void *_elem)
{
    dt_elem *elem = _elem;
    return elem[-1].str;
}

static void dt_dict_free_recurse(dt_elem *elem)
{
    if(elem->left)
        dt_dict_free_recurse(elem->left);
    if(elem->right)
        dt_dict_free_recurse(elem->right);
    free(elem->str);
    free(elem);
}

void dt_dict_free(dt_dict *_dict)
{
    dt_dict *dict = _dict;
    if(dict->root)
        dt_dict_free_recurse(dict->root);
    free(dict);
}
