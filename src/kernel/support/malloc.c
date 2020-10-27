// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
// 
//
//  Copyright (c) 2019-2020 checkra1n team
//  This file is part of pongoOS.
//
#include <pongo.h>
static lock malloc_lock, malloc_lock_temp;
static int malloc_lock_depth;
static struct task* malloc_lock_owner;
extern char preemption_over;

void __malloc_lock(struct _reent * unused) {
    if (preemption_over) return;
    
    lock_take(&malloc_lock_temp);
    
    if (malloc_lock_owner != task_current()) {
        lock_take(&malloc_lock);
    }
    malloc_lock_depth++;
    malloc_lock_owner = task_current();

    lock_release(&malloc_lock_temp);
}

void __malloc_unlock(struct _reent * unused) {
    if (preemption_over) return;
    
    lock_take(&malloc_lock_temp);
    malloc_lock_depth--;
    if (!malloc_lock_depth) {
        if (malloc_lock_owner != task_current()) {
            panic("invalid lock usage in malloc()");
        }
        lock_release(&malloc_lock);
        malloc_lock_owner = NULL;
    }
    lock_release(&malloc_lock_temp);
}
