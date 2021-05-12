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

/*

    Lock:
    [  63:2 pointer to last task with ownership ][ 1: busy ][ 0: held ]

    If last task with ownership == current_task and busy, zero out last task with ownership and yield

*/

#define IS_LOCK_HELD(_lock) ((*(volatile lock*)_lock) & 1)
#define IS_LOCK_BUSY(_lock) ((*(volatile lock*)_lock) & 2)
#define GET_LOCK_LAST_OWNER(_lock) ((struct task*)((*(volatile lock*)_lock) & (~3)))
#define SET_LOCK_HELD(_lock) do { (*(volatile lock*)_lock) |= 1; } while (0)
#define SET_LOCK_BUSY(_lock) do { (*(volatile lock*)_lock) |= 2; } while (0)
#define SET_LOCK_NOT_HELD(_lock) do { (*(volatile lock*)_lock) &= ~1; } while (0)
#define SET_LOCK_NOT_BUSY(_lock) do { (*(volatile lock*)_lock) &= ~2; } while (0)
#define SET_LOCK_LAST_OWNER(_lock, _task) do { (*(volatile lock*)_lock) &= 3; (*(volatile lock*)_lock) |= ((uint64_t)_task) & (~3);  } while (0)

extern uint64_t dis_int_count;

void lock_take(lock* _lock) {
    // takes a lock yielding until it acquires it
    extern char preemption_over;
    if(dis_int_count && !preemption_over)
    {
        panic("Called lock_take with interrupts disabled");
    }
    while (1) {
        if (!IS_LOCK_HELD(_lock)) {
            disable_interrupts(); // this should be atomic rather than this but we're not multicore so whatev
            if (!IS_LOCK_HELD(_lock)) {
                if (GET_LOCK_LAST_OWNER(_lock) == task_current() && IS_LOCK_BUSY(_lock)) {
                    SET_LOCK_LAST_OWNER(_lock, 0);
                    task_yield_asserted();
                    continue;
                } else {
                    SET_LOCK_HELD(_lock);
                    SET_LOCK_NOT_BUSY(_lock);
                    SET_LOCK_LAST_OWNER(_lock, task_current());
                    enable_interrupts();
                    return;
                }
            }
            enable_interrupts();
        } else {
            if (!IS_LOCK_BUSY(_lock)) {
                disable_interrupts();
                SET_LOCK_BUSY(_lock);
                enable_interrupts();
            }
        }
        task_yield();
    }
}
void lock_take_spin(lock* _lock) {
    // takes a lock spinning until it acquires it
    
    extern char preemption_over;
    if(dis_int_count && !preemption_over)
    {
        panic("Called lock_take_spin with interrupts disabled");
    }
    while (1) {
        if (!IS_LOCK_HELD(_lock)) {
            disable_interrupts(); // this should be atomic rather than this but we're not multicore so whatev
            if (!IS_LOCK_HELD(_lock)) {
                SET_LOCK_HELD(_lock);
                SET_LOCK_NOT_BUSY(_lock);
                SET_LOCK_LAST_OWNER(_lock, task_current());
                enable_interrupts();
                return;
            }
            enable_interrupts();
        } else {
            if (!IS_LOCK_BUSY(_lock)) {
                disable_interrupts();
                SET_LOCK_BUSY(_lock);
                enable_interrupts();
            }
        }
    }

}
void lock_release(lock* _lock) {
    // releases ownership on a lock
    disable_interrupts(); // this should be atomic rather than this but we're not multicore so whatev
    SET_LOCK_NOT_HELD(_lock);
    SET_LOCK_LAST_OWNER(_lock, task_current());
    enable_interrupts();
}
