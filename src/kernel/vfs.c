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
#include "vfs.h"
void filetable_reference(struct filetable* filetable) {
    if (!filetable) return;
    __atomic_fetch_add(&filetable->refcount, 1, __ATOMIC_SEQ_CST);
}
void filetable_release(struct filetable* filetable) {
    if (!filetable) return;
    uint32_t refcount = __atomic_fetch_sub(&filetable->refcount, 1, __ATOMIC_SEQ_CST);
    if (refcount == 1) {
#if DEBUG_REFCOUNT
        fiprintf(stderr, "freeing filetable: %p\n", filetable);
#endif
        for (uint32_t i=0; i < filetable->file_count; i++) {
            filedesc_release(filetable->file_table[i]);
        }
        free(filetable->file_table);
        free(filetable);
    }
}
void filedesc_reference(struct filedesc* fd) {
    if (!fd) return;
    __atomic_fetch_add(&fd->refcount, 1, __ATOMIC_SEQ_CST);
}
void filedesc_release(struct filedesc* fd) {
    if (!fd) return;
    uint32_t refcount = __atomic_fetch_sub(&fd->refcount, 1, __ATOMIC_SEQ_CST);
    if (refcount == 1) {
        file_release(fd->file);
        free(fd);
    }
}
void file_reference(struct file* file) {
    if (!file) return;
    __atomic_fetch_add(&file->refcount, 1, __ATOMIC_SEQ_CST);
}
void file_release(struct file* file) {
    if (!file) return;
    uint32_t refcount = __atomic_fetch_sub(&file->refcount, 1, __ATOMIC_SEQ_CST);
    if (refcount == 1) {
        free(file);
    }
}
struct file* file_create() {
    struct file* file = malloc(sizeof(struct file));
    bzero(file, sizeof(struct file));
    file->refcount = 1;
    return file;
}
struct filedesc* filedesc_create(struct file* file) {
    struct filedesc* filedesc = malloc(sizeof(struct filedesc));
    bzero(filedesc, sizeof(struct filedesc));
    file_reference(file);
    filedesc->file = file;
    filedesc->refcount = 1;
    return filedesc;
}
struct filetable* filetable_create(uint32_t size) {
    struct filetable* filetable = malloc(sizeof(struct filetable));
    bzero(filetable, sizeof(struct filetable));
    if (size > FILETABLE_MAX_SIZE) panic("filetable_create called with huge size");
    filetable->file_table = calloc(sizeof(struct filedesc*), size);
    filetable->refcount = 1;
    return filetable;
}
