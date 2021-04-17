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
#ifndef vfs_h
#define vfs_h

#include <pongo.h>

#define FILETABLE_MAX_SIZE 512

struct file;

struct fileops {
    void (*initialize)(struct file* file);
    void (*destroy)(struct file* file);
};

struct vnode {
    
};

struct file {
    lock lock;
    uint32_t refcount;
    struct fileops* fileops;
    void* fileinfo;
};

struct filedesc {
    struct file* file;
    uint32_t refcount;
};

struct filetable {
    struct filedesc** file_table;
    uint32_t file_count;
    uint32_t refcount;
};

void filetable_reference(struct filetable* filetable);
void filetable_release(struct filetable* filetable);

void filedesc_reference(struct filedesc* filetable);
void filedesc_release(struct filedesc* filetable);

void file_reference(struct file* filetable);
void file_release(struct file* filetable);

struct file* file_create();
struct filedesc* filedesc_create(struct file* file);
struct filetable* filetable_create(uint32_t size);

#endif
