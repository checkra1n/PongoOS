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
#ifndef task_h
#define task_h

union tte
{
    struct
    {
        uint64_t valid :  1,
                 table :  1,
                 attr  :  3,
                 ns    :  1,
                 ap    :  2,
                 sh    :  2,
                 af    :  1,
                 nG    :  1,
                 oa    : 36,
                 res00 :  3,
                 dbm   :  1,
                 cont  :  1,
                 pxn   :  1,
                 uxn   :  1,
                 ign0  :  4,
                 pbha  :  4,
                 ign1  :  1;
    };
    struct
    {
        uint64_t res01  : 12,
                 oahigh :  4,
                 nT     :  1,
                 res02  : 42,
                 pxntab :  1,
                 uxntab :  1,
                 aptab  :  2,
                 nstab  :  1;
    };
    uint64_t u64;
};

struct vm_space {
    uint64_t ttbr0;
    uint64_t ttbr1;
    uint64_t vm_space_base;
    uint64_t vm_space_end;
    uint8_t* vm_space_table;
    lock vm_space_lock;
    uint32_t refcount;
    struct vm_space* parent;
    uint64_t asid;
};
extern void vm_init();

struct proc {
    uint32_t refcount;
    struct filetable* file_table;
    struct vm_space* vm_space; // single tasks may have a different one, but proc_spawn_task() will use this one
    char name[64];
    struct task* task_list;
    lock lock;
};

struct task { // a task is a thread-like execution environment, executing under a given process and vmspace
    uint64_t x[30];
    uint64_t lr;
    uint64_t sp;
    uint64_t runcnt;
    uint64_t real_lr;
    uint64_t fp[20];
    uint64_t cpsr;
    uint64_t exception_stack;
    uint64_t is_spsel1;
    uint64_t ttbr1; // usermode
    uint64_t ttbr0; // ignored for now
    struct task* irq_ret;
    void* task_ctx;
    uint64_t irq_count;
    uint32_t irq_type;
    uint64_t wait_until;
    uint32_t sched_count;
    struct task* eq_next;
    uint64_t anchor[0];
    uint64_t el0_exception_stack;
    uint64_t pad;
    uint64_t initial_state[30];
    uint64_t t_flags; // task-specific flags, not used by task subsystem if not for internal tasks
    char name[32];
    uint32_t flags;
    struct task* next;
    struct task* prev;
    void (*exit_callback)();
    uint32_t refcount;
    int32_t critical_count;
    void (*fault_catch)();
    struct vm_space* vm_space;
    uint64_t user_stack;
    uint64_t entry_stack;
    uint64_t kernel_stack;
    uint64_t exception_stack_top;
    uint64_t entry;
    uint32_t pid;
    uint32_t gencount;
    lock task_lock;
    struct proc* proc;
    struct task* proc_task_list_next; // only tasks created with proc_create_task are queued here
};
extern void task_alloc_fast_stacks(struct task* task);

#endif /* task_h */
