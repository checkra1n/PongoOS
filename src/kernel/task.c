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
#include <errno.h>
#include <stdlib.h>
#include <pongo.h>

extern void task_load(struct task* to_task);
extern void task_load_asserted(struct task* to_task);
uint64_t scheduler_ticks = 0;
volatile uint64_t preemption_counter = 0;
extern void _task_switch(struct task* new);
extern void _task_switch_asserted(struct task* new);

extern uint64_t dis_int_count, fiqCount;
uint64_t served_irqs;
volatile struct task* sched_array[32];
volatile char has_preempted = 0;

void task_assert_unlinked(struct task* task) {
    return;
}

void task_suspend_self() {
    disable_interrupts();
    task_unlink(task_current());
    task_yield_asserted();
}
void task_suspend_self_asserted() {
    task_unlink(task_current());
    task_yield_asserted();
}

volatile uint32_t task_timer_ctr;
extern uint32_t do_preempt, preemption_on;
void task_timer_fired() {
    task_timer_ctr ++;
}

struct task* irqvecs[0x200];
void register_irq_handler(uint16_t irq_v, struct task* irq_handler)
{
    if (irq_v >= 0x1ff) panic("invalid irq");
    task_reference(irq_handler);
    irqvecs[irq_v] = irq_handler;
}

typedef struct
{
    char name[32];
    uint64_t runcnt;
    uint32_t pid;
    uint32_t flags;
    uint64_t irq_count;
} task_info_t;

void task_list(const char* cmd, char* arg) {
    extern struct task sched_task;
    task_info_t *tasks_copy = NULL;
    task_info_t *irq_copy = NULL;

    // First determine malloc size uninterruptible
    disable_interrupts();
    size_t ntasks = 0, nirq = 0;
    struct task* cur_task = &sched_task;
    do {
        if (!(cur_task->flags & (TASK_HAS_EXITED|TASK_IRQ_HANDLER))) {
            ++ntasks;
        }
        cur_task = cur_task->next;
    } while (cur_task != &sched_task);
    for (int i=0; i<0x1ff; i++) {
        if (irqvecs[i]) {
            ++nirq;
        }
    }
    enable_interrupts();

retry:;
    // Alloc mem interruptible
    if(!tasks_copy)
    {
        tasks_copy = malloc(ntasks * sizeof(*tasks_copy));
        if(!tasks_copy)
        {
            panic("malloc(tasks_copy): %d", errno);
        }
    }
    if(!irq_copy)
    {
        irq_copy = malloc(nirq * sizeof(*irq_copy));
        if(!irq_copy)
        {
            panic("malloc(irq_copy): %d", errno);
        }
    }

    disable_interrupts();
    // Verify that the size hasn't changed
    size_t nt = 0, ni = 0;
    cur_task = &sched_task;
    do {
        if (!(cur_task->flags & (TASK_HAS_EXITED|TASK_IRQ_HANDLER))) {
            ++nt;
        }
        cur_task = cur_task->next;
    } while (cur_task != &sched_task);
    for (int i=0; i<0x1ff; i++) {
        if (irqvecs[i]) {
            ++ni;
        }
    }
    // Otherwise realloc
    if(nt != ntasks || ni != nirq)
    {
        enable_interrupts();
        if(nt != ntasks)
        {
            ntasks = nt;
            free(tasks_copy);
            tasks_copy = NULL;
        }
        if(ni != nirq)
        {
            nirq = ni;
            free(irq_copy);
            irq_copy = NULL;
        }
        goto retry;
    }
    // Copy data
    nt = 0;
    cur_task = &sched_task;
    do {
        if (!(cur_task->flags & (TASK_HAS_EXITED|TASK_IRQ_HANDLER))) {
            strlcpy(tasks_copy[nt].name, cur_task->name, sizeof(tasks_copy[nt].name));
            tasks_copy[nt].runcnt = cur_task->runcnt;
            tasks_copy[nt].pid    = cur_task->pid;
            tasks_copy[nt].flags  = cur_task->flags;
            ++nt;
        }
        cur_task = cur_task->next;
    } while (cur_task != &sched_task);
    ni = 0;
    for (int i=0; i<0x1ff; i++) {
        if (irqvecs[i]) {
            strlcpy(irq_copy[ni].name, irqvecs[i]->name, sizeof(irq_copy[ni].name));
            irq_copy[ni].runcnt = irqvecs[i]->irq_count;
            irq_copy[ni].pid    = i;
            irq_copy[ni].flags  = irqvecs[i]->flags;
            irq_copy[ni].irq_count  = irqvecs[i]->irq_count;
            ++ni;
        }
    }
    // Get these too while we're uninterruptible
    uint64_t a = *(volatile uint64_t*)&served_irqs,
             b = *(volatile uint64_t*)&fiqCount,
             c = *(volatile uint64_t*)&preemption_counter,
             d = (get_ticks() - gBootTimeTicks) / (2400 * 1000);
    enable_interrupts();

    // Now dump it all out
    iprintf("served irqs: %lld, caught fiqs: %lld, preempt: %lld, uptime: %lld.%llds\n", a, b, c, d/10, d%10);
    for(int i = 0; i < ntasks; ++i)
    {
        task_info_t *t = &tasks_copy[i];
        iprintf("%10s | task %d | runcnt = %llx | flags = %s, %s\n", t->name[0] ? t->name : "unknown", t->pid, t->runcnt, t->flags & TASK_PREEMPT ? "preempt" : "coop", t->flags & TASK_LINKED ? "run" : "wait");
    }
    for(int i = 0; i < nirq; ++i)
    {
        task_info_t *t = &irq_copy[i];
        char* nm = t->name[0] ? t->name : "unknown";
        iprintf("%10s (%d) | runcnt: %lld | irq: %d | irqcnt: %llu | flags: %s, %s\n", nm, t->pid, t->runcnt, i, t->irq_count, t->flags & TASK_PREEMPT ? "preempt" : "coop", t->flags & TASK_LINKED ? "run" : "wait");
    }

    free(tasks_copy);
    free(irq_copy);
}
void task_irq_teardown() {
    for (int i=0; i<0x1ff; i++) {
        if (irqvecs[i]) {
            mask_interrupt(i);
        }
    }
}

__attribute__((noinline)) void task_switch_irq(struct task* new)
{
    if (!(new->flags & TASK_IRQ_HANDLER)) panic("we are not entering an irq task");
    if (new->flags & TASK_PREEMPT) {
        new->irq_count++;
        task_link(new); // preempting IRQ handlers aren't switched into immediately, but on next scheduler run
        task_set_sched_head(new);
        served_irqs++;
        return;
    }
    if (new->irq_ret) panic("the irq handler wasn't exited correctly?!");
    new->irq_ret = task_current();
    new->irq_count++;
    _task_switch(new);
    if (new->irq_ret != task_current()) {
        puts("======== IRQ SCHEDULER FAULT ========");
        iprintf("cur_task: %p != irq_ret: %p\n", task_current(), new->irq_ret);
        panic("task_current() is not set correctly");
    }
    new->irq_ret = NULL;
    if (new->flags & TASK_MASK_NEXT_IRQ) new->flags &= ~TASK_MASK_NEXT_IRQ;
    else unmask_interrupt(new->irq_type); // re-arm IRQ
    served_irqs++;
}
__attribute__((noinline)) void task_irq_dispatch(uint32_t intr) {
    struct task* irq_handler = irqvecs[intr & 0x1FF];
    if (irq_handler) {
        irq_handler->irq_type = intr & 0x1ff;
        task_switch_irq(irq_handler);
    } else {
        iprintf("couldn't find irq handler for %x\n", intr);
        panic("task_irq_dispatch");
    }
}

extern struct task sched_task;
extern uint32_t preempt_ctr;
void task_yield_preemption() {
    disable_interrupts();
    if (dis_int_count != 1) {
        panic("task yielded with interrupts held");
    }
    preempt_ctr++;
    _task_switch_asserted(&sched_task);
    disable_interrupts();
    if (dis_int_count != 1) {
        panic("sched returned with interrupts held");
    }
    dis_int_count = 0;
}

void task_wait() {
    disable_interrupts();
    if (dis_int_count != 1) {
        panic("task yielded with interrupts held");
    }
    _task_switch_asserted(&sched_task);
}

void task_crash_internal(const char* reason, va_list va) {
    fiprintf(stderr, "pongoOS: killing task |%s| due to crash: ", task_current()->name[0] ? task_current()->name : "<unknown>");
    vfiprintf(stderr, reason, va);
    putc('\n', stderr);
    task_unlink(task_current());
    task_current()->flags |= TASK_HAS_CRASHED;

    task_exit_asserted();
}
void task_crash(const char* reason, ...) {
    disable_interrupts();
    va_list va;
    va_start(va, reason);
    task_crash_internal(reason, va);
    va_end(va);
}
void task_crash_asserted(const char* reason, ...) {
    va_list va;
    va_start(va, reason);
    task_crash_internal(reason, va);
    va_end(va);
}
void task_exit() {
    disable_interrupts();
    task_exit_asserted();
}
void task_exit_asserted() {
    if (task_current()->flags & TASK_IRQ_HANDLER) {
        if (task_current()->flags & TASK_HAS_CRASHED) {
            panic("irq handler crashed!");
        } else {
            panic("irq handler exited! please use task_irq_exit!");
        }
    }
    task_current()->flags |= TASK_HAS_EXITED;
    if (!(task_current()->flags & TASK_CAN_EXIT)) {
        panic("required task exited!");
    }
    task_unlink(task_current());
    if (task_current()->exit_callback) task_current()->exit_callback();
    if (task_current()->flags & TASK_RESTART_ON_EXIT) task_restart_and_link(task_current());
    task_load_asserted(&sched_task);
    panic("never reached");
}
void task_entry() {
    void (*entry)() = (void*)task_current()->entry;
    entry();
    task_exit();
}
volatile uint32_t gPid = 1;


void task_restart_and_link(struct task* task) {
    disable_interrupts();
    task->sp = (uint64_t)(&task->anchor);
    task->sp -= 0x80;
    task->sp &= ~0xF;
    task->lr = (uint64_t)task_entry;
    memset(&task->x[0], 0, 30 * 8);
    task->flags &= ~(TASK_HAS_EXITED|TASK_HAS_CRASHED);
    task_link(task);
    enable_interrupts();
}


void task_register_unlinked(struct task* task, void (*entry)()) {
    memset(task, 0, offsetof(struct task, anchor));
    task->refcount = TASK_REFCOUNT_GLOBAL;
    task->sp = (uint64_t)(&task->anchor);
    task->sp -= 0x80;
    task->sp &= ~0xF;
    task->entry = (uint64_t)entry;
    task->lr = (uint64_t)task_entry;
    task->flags &= TASK_WAS_LINKED | TASK_HAS_EXITED;
    task->flags |= TASK_PREEMPT;
    disable_interrupts();
    task->pid = gPid++;
    enable_interrupts();
}

void task_register_irq(struct task* task, void (*entry)(), int irq_id) {
    disable_interrupts();
    task_register_unlinked(task, entry);
    task->flags |= TASK_IRQ_HANDLER;
    task->flags &= ~TASK_PREEMPT;
    register_irq_handler(irq_id, task);
    unmask_interrupt(irq_id);
    enable_interrupts();
}
void task_register_preempt_irq(struct task* task, void (*entry)(), int irq_id) {
    disable_interrupts();
    task_register_unlinked(task, entry);
    task->flags |= TASK_IRQ_HANDLER;
    task->flags |= TASK_PREEMPT;
    register_irq_handler(irq_id, task);
    unmask_interrupt(irq_id);
    enable_interrupts();
}
void task_register(struct task* task, void (*entry)()) {
    disable_interrupts();
    task_register_unlinked(task, entry);
    task->flags |= TASK_PREEMPT | TASK_CAN_EXIT;
    task_link(task);
    enable_interrupts();
}
void task_register_coop(struct task* task, void (*entry)()) {
    disable_interrupts();
    task_register_unlinked(task, entry);
    task->flags &= ~TASK_PREEMPT;
    task->flags |= TASK_CAN_EXIT;
    task_link(task);
    enable_interrupts();
}

struct task* task_create(const char* name, void (*entry)()) {
    struct task* task = malloc(sizeof(struct task));
    bzero((void*) task, sizeof(struct task));
    task_register(task, entry);
    strncpy(task->name, name, 32);
    task->refcount = 1;
    return task;
}
struct task* task_create_extended(const char* name, void (*entry)(), int task_type, int arg) {
    task_type &= TASK_TYPE_MASK;
    
    struct task* task = malloc(sizeof(struct task));
    bzero((void*) task, sizeof(struct task));

    task_register_unlinked(task, entry);
    strncpy(task->name, name, 32);
    task->flags |= task_type & ~TASK_LINKED;
    task->flags &= ~TASK_PREEMPT;
    if (task_type & TASK_PREEMPT) task->flags |= TASK_PREEMPT;
    task->refcount = 1;
    
    if ((task_type & TASK_IRQ_HANDLER) && arg) { /* register as IRQ handler */
        disable_interrupts();
        register_irq_handler(arg, task);
        unmask_interrupt(arg);
        enable_interrupts();
    } else /* TASK_LINKED and TASK_IRQ_HANDLER as type are mutually exclusive */
    if (task_type & TASK_LINKED) { /* link */
        disable_interrupts();
        task_link(task);
        enable_interrupts();
    }
    return task;
}
void task_bind_to_irq(struct task* task, int irq) {
    disable_interrupts();
    register_irq_handler(irq, task);
    unmask_interrupt(irq);
    enable_interrupts();
}
void task_reference(struct task* task) {
    if (!task) return;
    if (task->refcount == TASK_REFCOUNT_GLOBAL) return;
    __atomic_fetch_add(&task->refcount, 1, __ATOMIC_SEQ_CST);
}
void task_release(struct task* task) {
    if (!task) return;
    if (task->refcount == TASK_REFCOUNT_GLOBAL) return;
    uint32_t refcount = __atomic_fetch_sub(&task->refcount, 1, __ATOMIC_SEQ_CST);
    if (refcount == 0) {
        disable_interrupts();
        if (task_current() == task) panic("trying to free the current task");
        if (task->flags & TASK_IRQ_HANDLER) panic("can't free an IRQ handling task");
        if (task->flags & TASK_LINKED) task_unlink(task);
        free(task);
        enable_interrupts();
    }
}


void task_exit_irq()
{
    if (task_current()->flags & TASK_PREEMPT) {
        disable_interrupts();
        if (!(task_current()->flags & TASK_LINKED)) panic("task_exit_irq on unlinked preempt irq handler?");
        task_unlink(task_current());
        if (task_current()->flags & TASK_MASK_NEXT_IRQ) task_current()->flags &= ~TASK_MASK_NEXT_IRQ;
        else unmask_interrupt(task_current()->irq_type); // re-arm IRQ
        if (dis_int_count != 1) {
            panic("irq handler yielded with interrupts held");
        }
        return _task_switch_asserted(&sched_task);
    }
    if (!(task_current()->flags & TASK_IRQ_HANDLER))  return task_yield();
    if (!task_current()->irq_ret) panic("task_exit_irq must be invoked from enabled irq context");
    _task_switch(task_current()->irq_ret);
}
extern uint64_t dis_int_count;
void task_switch(struct task* new)
{
    if (new->flags & TASK_IRQ_HANDLER) {
        return;
    }
    if (dis_int_count) return; // do not allow task yield in irq context
    _task_switch(new);
}

void task_yield_asserted() {
    _task_switch_asserted(&sched_task);
}
void _task_yield() {
    _task_switch(&sched_task);
}
void task_yield() {
    if (dis_int_count) {
        return; // no-preempt
    }
    disable_interrupts();
    _task_switch_asserted(&sched_task);
}


/*

    Name: task_link
    Description: adds a task in the sched queue

*/
extern struct task* pongo_sched_head;
void task_link(struct task* task) {
    disable_interrupts();
    task->flags &= ~TASK_HAS_EXITED;
    if (!(task->flags & TASK_WAS_LINKED)) {
        if (pongo_sched_head) {
            task->prev = pongo_sched_head;
            task->next = pongo_sched_head->next;
            task->prev->next = task;
            task->next->prev = task;
        } else {
            task->prev = task;
            task->next = task;
        }
        pongo_sched_head = task;
        task->flags |= TASK_WAS_LINKED;
    }
    task->flags |= TASK_LINKED;
    enable_interrupts();
}

/*

    Name: task_set_sched_head
    Description: moves a task to the scheduler queue head

*/

void task_set_sched_head(struct task* task) {
    disable_interrupts();
    if (!(task->flags & TASK_LINKED)) panic ("task was not linked but was asked to move to head of schedqueue");
    pongo_sched_head = task;
    enable_interrupts();
}

/*

    Name: task_unlink
    Description: removes a task from the sched queue

*/

void task_unlink(struct task* task) {
    disable_interrupts();
    task->flags &= ~TASK_LINKED;
    enable_interrupts();
}

void event_wait(struct event* ev) {
    disable_interrupts();
    task_current()->eq_next = ev->task_head;
    ev->task_head = task_current();
    task_unlink(task_current());
    task_yield_asserted();
}
void event_wait_asserted(struct event* ev) {
    task_current()->eq_next = ev->task_head;
    ev->task_head = task_current();
    task_unlink(task_current());
    task_yield_asserted();
}
void event_fire(struct event* ev) {
    disable_interrupts();
    struct task* to_link = ev->task_head;
    while (to_link) {
        task_link(to_link);
        to_link = to_link->eq_next;
    }
    ev->task_head = NULL;
    enable_interrupts();
}
