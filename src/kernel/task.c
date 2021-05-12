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
    if (irqvecs[irq_v]) task_release(irqvecs[irq_v]);
    if (irq_handler) task_reference(irq_handler);
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
    extern uint64_t ppages;
    extern uint64_t free_pages;
    extern uint64_t wired_pages;
    extern uint64_t pages_in_freelist;
    extern uint64_t paging_requests;
    extern uint64_t heap_base;
    extern uint64_t heap_end;

    // Get these too while we're uninterruptible
    uint64_t a = *(volatile uint64_t*)&served_irqs,
             b = *(volatile uint64_t*)&fiqCount,
             c = *(volatile uint64_t*)&preemption_counter,
             d = (get_ticks() - gBootTimeTicks) / (2400 * 1000),
             e = ppages, f = free_pages, g = wired_pages, h = (heap_end - heap_base) >> 14, i = paging_requests;
    enable_interrupts();

    // Now dump it all out
    iprintf("=+= System Information ===\n | served irqs: %lld, caught fiqs: %lld, preempt: %lld, uptime: %lld.%llds\n | free pages: %lld (%lld MB), inuse: %lld (%lld MB), paged: %lld\n | heap: %lld (%lld MB), wired: %lld (%lld MB), total: %lld (%lld MB)\n=+=    Process List    ===\n", a, b, c, d/10, d%10, f, f / 0x40, e - f, (e - f) / 0x40, i, h, h / 0x40, g, g / 0x40, e, e / 0x40);
    for(int i = 0; i < ntasks; ++i)
    {
        task_info_t *t = &tasks_copy[i];
        iprintf(" | %7s | task %d | runcnt = %llx | flags = %s, %s\n", t->name[0] ? t->name : "unknown", t->pid, t->runcnt, t->flags & TASK_PREEMPT ? "preempt" : "coop", t->flags & TASK_LINKED ? "run" : "wait");
    }
    iprintf("=+=    IRQ Handlers    ===\n");
    for(int i = 0; i < nirq; ++i)
    {
        task_info_t *t = &irq_copy[i];
        char* nm = t->name[0] ? t->name : "unknown";
        iprintf(" | %7s (%d) | runcnt: %lld | irq: %d | irqcnt: %llu | flags: %s, %s\n", nm, t->pid, t->runcnt, i, t->irq_count, t->flags & TASK_PREEMPT ? "preempt" : "coop", t->flags & TASK_LINKED ? "run" : "wait");
    }
    iprintf("=+=   Loaded modules   ===\n");
    extern void pongo_module_print_list();
    pongo_module_print_list();
    iprintf("=+========================\n");
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
    fiprintf(stderr, "pongoOS: killing task |%s| (proc: %s): ", task_current()->name[0] ? task_current()->name : "<unknown>", task_current()->proc ? task_current()->proc->name : "<unknown>");
    vfiprintf(stderr, reason, va);
    putc('\n', stderr);
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

void task_critical_enter() {
    struct task *t = task_current();
    if(t)
    {
        t->critical_count++;
    }
}
void task_critical_exit() {
    struct task *t = task_current();
    if(t)
    {
        if (!t->critical_count) {
            panic("invalid call to task_critical_exit");
        }
        t->critical_count--;
    }
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
    if (task_current()->critical_count) {
        panic("crashed in critical section");
    }
    if (!(task_current()->flags & TASK_CAN_EXIT)) {
        panic("required task exited!");
    }
    task_unlink(task_current());
    if (task_current()->exit_callback) task_current()->exit_callback();
    if (task_current()->flags & TASK_RESTART_ON_EXIT) task_restart_and_link(task_current());
    else
        task_current()->flags |= TASK_PLEASE_DEREF;

    task_load_asserted(&sched_task);
    panic("never reached");
}

void task_spawn(struct task* initial_task) { // moves a task to a new addess space (EL0 task)
    lock_take(&initial_task->task_lock);
    if (initial_task->vm_space) {
        initial_task->vm_space = vm_create(initial_task->vm_space);
    } else {
        initial_task->vm_space = vm_create(NULL);
    }
    initial_task->user_stack = 0;
    initial_task->ttbr0 = initial_task->vm_space->ttbr0;
    initial_task->ttbr1 = initial_task->vm_space->ttbr1 | initial_task->vm_space->asid;
    lock_release(&initial_task->task_lock);
}
struct task* proc_create_task(struct proc* proc, void* entryp) {
    struct task* task = task_create_extended(proc->name, (void*)entryp, TASK_PREEMPT|TASK_CAN_EXIT|TASK_FROM_PROC, (uint64_t)proc);
    lock_take(&proc->lock);
    task->proc_task_list_next = proc->task_list;
    proc->task_list = task;
    lock_release(&proc->lock);
    return task;
}

extern void task_entry_j(void(*entry)(), uint64_t stack, void (*retn)(), uint64_t cpsr);
void task_fault_stack(struct task* task) {
    if (!task->user_stack) {
        uint64_t addr = 0;
        if (vm_allocate(task->vm_space, &addr, 0x40000, VM_FLAGS_ANYWHERE) != KERN_SUCCESS) panic("task_register_unlinked: couldn't allocate stack");
        
        vm_space_map_page_physical_prot(task->vm_space, addr, 0, 0); // place guard page
        vm_space_map_page_physical_prot(task->vm_space, addr+0x3c000, 0, 0); // place guard page
        
        task->user_stack = addr;
        task->entry_stack = addr + 0x37800;
    }
}
int ct = 0;
void task_entry() {
    struct task* task = task_current();
    if (!task) panic("task_entry: no task");
    task_fault_stack(task);
    if (!task->entry_stack) {
        panic("task_entry: no stack");
    }
    
    if (task->vm_space == &kernel_vm_space) {
        task->cpsr = 0x4; // EL1 SP0
        
        void (*entry)() = (void*)task->entry;
        task_entry_j(entry, task->entry_stack, task_exit, task->cpsr);
    } else {
        task->cpsr = 0; // EL0
        
        void (*entry)() = (void*)task->entry;
        task_entry_j(entry, task->entry_stack, 0, task->cpsr);
    }
    
    panic("unreachable");
}
volatile uint32_t gPid = 1;

#define KERN_STACK_SIZE 0x8000

void* kernel_stack_allocate_new() {
    uint64_t stack_size = KERN_STACK_SIZE + 2 * PAGE_SIZE;
    uint64_t phys_backing = alloc_phys(KERN_STACK_SIZE);
    uint64_t vma_backing = linear_kvm_alloc(stack_size);
    
    vm_space_map_page_physical_prot(&kernel_vm_space, vma_backing, 0, 0); // guard page
    for (uint64_t offset = 0; offset < stack_size - PAGE_SIZE * 2; offset += PAGE_SIZE) {
        vm_space_map_page_physical_prot(&kernel_vm_space, vma_backing + PAGE_SIZE + offset, phys_backing + offset, PROT_READ|PROT_WRITE|PROT_KERN_ONLY);
    }
    vm_space_map_page_physical_prot(&kernel_vm_space, vma_backing + KERN_STACK_SIZE + PAGE_SIZE, 0, 0); // guard page

    return (void*)(vma_backing + PAGE_SIZE + KERN_STACK_SIZE - 0x400);
}

void* stack_freelist = NULL;

void* kernel_stack_allocate() {
    void* stack = NULL;
    disable_interrupts();
    if (stack_freelist) {
        stack = stack_freelist;
        stack_freelist = *(void**)stack;
    } else {
        stack = kernel_stack_allocate_new();
    }
    enable_interrupts();
    return stack;
}
void kernel_stack_free(void* stack) {
    disable_interrupts();
    *(void**)stack = stack_freelist;
    stack_freelist = stack;
    enable_interrupts();
}


void task_alloc_fast_stacks(struct task* task) {
    if (!task->kernel_stack) {
        task->kernel_stack = (uint64_t)kernel_stack_allocate();
    }
    if (!task->exception_stack_top) {
        task->exception_stack_top = (uint64_t)kernel_stack_allocate();
    }
    task->exception_stack = (uint64_t)task->exception_stack_top;
    task->exception_stack &= ~0xf;
    task->el0_exception_stack = task->kernel_stack;
    task->el0_exception_stack &= ~0xf;
}
void task_set_entry(struct task* task) {
    task_alloc_fast_stacks(task);

    task->lr = (uint64_t)task_entry;
    task->sp = (uint64_t)task->kernel_stack;
    task->sp &= ~0xf;
    task->ttbr0 = task->vm_space->ttbr0;
    task->ttbr1 = task->vm_space->ttbr1 | task->vm_space->asid;
}

void task_restart(struct task* task) {
    disable_interrupts();
    memset(task, 0, offsetof(struct task, anchor));
    task_set_entry(task);
    task->gencount++;
    task->flags &= ~(TASK_HAS_EXITED|TASK_HAS_CRASHED);
    enable_interrupts();
}
void task_restart_and_link(struct task* task) {
    disable_interrupts();
    task_restart(task);
    task_link(task);
    enable_interrupts();
}


void task_register_unlinked(struct task* task, void (*entry)()) {
    memset(task, 0, offsetof(struct task, anchor));

    if (task->proc) {
        if (!task->vm_space)
            task->vm_space = vm_reference(task->proc->vm_space);
    } else {
        if (!task->vm_space)
            task->vm_space = vm_reference(task_current()->vm_space);
        task->proc = task_current()->proc;
        proc_reference(task->proc);
    }
    
    task->refcount = TASK_REFCOUNT_GLOBAL;
    task_set_entry(task);
    task->entry = (uint64_t)entry;
    task->flags &= TASK_WAS_LINKED | TASK_HAS_EXITED;
    task->flags |= TASK_PREEMPT;
    task->gencount = 0;

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
    disable_interrupts();
    bzero((void*) task, sizeof(struct task));
    task_register(task, entry);
    strncpy(task->name, name, 32);
    task->refcount = 1;
    enable_interrupts();
    return task;
}
struct task* task_create_extended(const char* name, void (*entry)(), int task_type, uint64_t arg) {
    struct proc* proc = task_current()->proc;
    if (task_type & TASK_FROM_PROC) {
        proc = (struct proc*) arg;
        arg = 0;
    }
    
    task_type &= TASK_TYPE_MASK;

    struct task* task = malloc(sizeof(struct task));
    bzero((void*) task, sizeof(struct task));
    
    proc_reference(proc);
    task->proc = proc;
    task_register_unlinked(task, entry);
    strncpy(task->name, name, 32);
    task->flags |= task_type & ~TASK_LINKED;
    task->flags &= ~TASK_PREEMPT;
    if (task_type & TASK_PREEMPT) task->flags |= TASK_PREEMPT;
    task->refcount = 1;

    if (task_type & TASK_SPAWN) {
        if (task_type & TASK_IRQ_HANDLER) {
            panic("irq handlers must be bound to the kernel vmspace");
        }
        task_spawn(task);
    }
    
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
    if (refcount == 1) {
        disable_interrupts();
        if (task_current() == task) panic("trying to free the current task");
#if DEBUG_REFCOUNT
        fiprintf(stderr, "freeing task: %p (%s)\n", task, task->name);
#endif
        if (task->proc) {
            struct task** el = &task->proc->task_list;
            while (*el) {
                if (*el == task) {
                    *el = task->proc_task_list_next;
                    break;
                }
                el = &((*el)->proc_task_list_next);
            }
        }
        kernel_stack_free((void*)task->kernel_stack);
        kernel_stack_free((void*)task->exception_stack_top);
        vm_deallocate(task->vm_space, task->user_stack, 0x40000);
        task_real_unlink(task);
        vm_release(task->vm_space);
        proc_release(task->proc);
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

void task_real_unlink(struct task* task) {
    disable_interrupts();
    if (task->flags & TASK_WAS_LINKED) {
        if (task == pongo_sched_head) {
            if (task == task->next) {
                pongo_sched_head = NULL;
            } else {
                pongo_sched_head = task->next;
            }
        }

        task->prev->next = task->next;
        task->next->prev = task->prev;
        task->flags &= ~(TASK_WAS_LINKED|TASK_LINKED);
    }
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
struct proc* proc_create(struct proc* parent, const char* procname, uint32_t flags) {
    struct proc* proc = malloc(sizeof(struct proc));
    bzero(proc, sizeof(struct proc));
    strncpy(proc->name, procname, 64);
    if (parent) {
        proc->file_table = parent->file_table;
        proc->vm_space = vm_create(parent->vm_space);
        filetable_reference(proc->file_table);
    } else {
        proc->file_table = filetable_create(FILETABLE_MAX_SIZE);
        if (!(flags & PROC_NO_VM)) {
            proc->vm_space = vm_create(NULL);
        } else {
            proc->vm_space = NULL;
        }
    }
    proc->refcount = 1;
    return proc;
}
void proc_reference(struct proc* proc) {
    if (!proc) return;
    __atomic_fetch_add(&proc->refcount, 1, __ATOMIC_SEQ_CST);
}
void proc_release(struct proc* proc) {
    if (!proc) return;
    uint32_t refcount = __atomic_fetch_sub(&proc->refcount, 1, __ATOMIC_SEQ_CST);
    if (refcount == 1) {
#if DEBUG_REFCOUNT
        fiprintf(stderr, "freeing proc %s @ %p\n", proc->name, proc);
#endif
        struct task* to_free = proc->task_list;
        while (to_free) {
            struct task* tc = to_free;
            to_free = tc->proc_task_list_next;
            tc->proc_task_list_next = NULL;
            task_release(tc);
        }

        vm_release(proc->vm_space);
        filetable_release(proc->file_table);
        free(proc);
    }
}
