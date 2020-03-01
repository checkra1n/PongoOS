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
#define LL_KTRW_INTERNAL 1
#include <pongo.h>

extern void task_load(struct task* to_task);
extern void task_load_asserted(struct task* to_task);
uint64_t scheduler_ticks = 0;
volatile uint64_t preemption_counter = 0;
extern void _task_switch(struct task* new);
extern void _task_switch_asserted(struct task* new);

extern uint64_t dis_int_count, fiqCount;
void schedule_explicit(struct task* task) {
    wdt_enable();
    scheduler_ticks++;
    timer_rearm();
    if (dis_int_count != 1) panic("scheduler about to switch with ints held");
    _task_switch_asserted(task);
}
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
    irqvecs[irq_v] = irq_handler;
}

void task_list(const char* cmd, char* arg) {
    disable_interrupts();
    iprintf("served irqs: %lx, caught fiqs: %lx, preempt: %lx, sched: %lx\n", served_irqs, fiqCount, preemption_counter, scheduler_ticks);
    extern struct task sched_task;
    struct task* cur_task = &sched_task;
    do {
        if (!(cur_task->flags & (TASK_HAS_EXITED|TASK_IRQ_HANDLER))) {
            char* nm = cur_task->name[0] ? cur_task->name : "unknown";
            iprintf("%10s | task %d | runcnt = %lx | flags = %s, %s\n", nm, cur_task->pid, cur_task->runcnt, cur_task->flags & TASK_PREEMPT ? "preempt" : "coop", cur_task->flags & TASK_LINKED ? "run" : "wait");
	}
        cur_task = cur_task->next;
    } while (cur_task != &sched_task);

    for (int i=0; i<0x1ff; i++) {
        if (irqvecs[i]) {
            char* nm = irqvecs[i]->name[0] ? irqvecs[i]->name : "unknown";
            iprintf("%10s | irq: %d, irq_count: %lx, flags: %s\n", nm, i, irqvecs[i]->irq_count, irqvecs[i]->flags & TASK_PREEMPT ? "preempt" : "sync");	
	}
    }
    enable_interrupts();
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
void task_exit() {
    disable_interrupts();
    task_current()->flags |= TASK_HAS_EXITED;
    task_unlink(task_current());
    task_yield_asserted();
    panic("dead task re-scheduled?!");
}
void task_entry() {
    void (*entry)() = (void*)task_current()->entry;
    entry();
    task_exit();
}
volatile uint32_t gPid = 1;
void task_register_unlinked(struct task* task, void (*entry)()) {
    memset(task, 0, offsetof(struct task, anchor));
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
    task->flags |= TASK_PREEMPT;
    task_link(task);
    enable_interrupts();
}
void task_register_coop(struct task* task, void (*entry)()) {
    disable_interrupts();
    task_register_unlinked(task, entry);
    task->flags &= ~TASK_PREEMPT;
    task_link(task);
    enable_interrupts();
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

