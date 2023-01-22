/*
 * pongoOS - https://checkra.in
 *
 * Copyright (C) 2019-2023 checkra1n team
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
#include "fuse/fuse_private.h"
#include "dt/dt_private.h"
#include "recfg/recfg_soc.h"
#include "pongo.h"
#include <reent.h>

boot_args *gBootArgs;
uint64_t gTopOfKernelData;
void *gEntryPoint;
volatile char gBootFlag = 0;
uint64_t gIOBase;

char* gDevType;
uint64_t gESTS;

struct task sched_task = {.name = "sched"};
struct task pongo_task = {.name = "main"};

/*

    Name: pongo_fiq_handler
    Description: called every LLKTRW_QUANTA (1ms at the time of writing this)

*/

int pongo_fiq_handler() {
    timer_rearm();
    return !!(task_current()->flags & TASK_PREEMPT);
}

/*

    Name: pongo_reinstall_vbar
    Description: sets the exception vector

*/

__attribute__((noinline)) void pongo_reinstall_vbar() {
    set_vbar_el1((uint64_t)&exception_vector);
}

/*

    Name: pongo_sched_tick
    Description: every time we return from an exception back into the sched task, this function is invoked
    Return values: 0 if a task got volountarily yielded or we did not schedule, 1 if we got preempted, 2 if we looped around list

*/

extern void _task_switch(struct task* new);
extern void _task_switch_asserted(struct task* new);

uint32_t preempt_ctr;
uint32_t sched_tick_index = 0;

struct task* pongo_sched_head;

char pongo_sched_tick() {
    char rvalue = 0;
    disable_interrupts();
    if (!pongo_sched_head) panic("no tasks to schedule");
    if (pongo_sched_head == &sched_task) {
        pongo_sched_head = pongo_sched_head->next;
        rvalue = 2; // if we got here
        goto out;
    }
    if (pongo_sched_head) {
        struct task* volatile tsk = pongo_sched_head;
        pongo_sched_head = pongo_sched_head->next;
        if (tsk->flags & TASK_PLEASE_DEREF) {
            tsk->flags &= ~TASK_PLEASE_DEREF;
            task_release(tsk);
        } else
        if (tsk->flags & TASK_LINKED) {
            _task_switch_asserted(tsk);
            disable_interrupts();
            if (preempt_ctr) {
                rvalue = 1;
                preempt_ctr = 0;
            }
        }

    }
out:
    enable_interrupts();
    return rvalue;
}

/*

    Name: pongo_entry_cached
    Description: once we rebase PC into the cacheable view we branch into this function; this represents the main ll-ktrw function

*/

extern void _task_set_current(struct task* t);
extern struct vm_space kernel_vm_space;
extern void _task_switch_asserted(struct task* new);

char soc_name[9] = {};
uint32_t socnum = 0x0;
void (*sep_boot_hook)(void);

__attribute__((noinline)) void pongo_entry_cached()
{
    extern char preemption_over;
    preemption_over = 1;

    // Literally everything depends on this
    dt_init((void*)((uint64_t)gBootArgs->deviceTreeP - gBootArgs->virtBase + gBootArgs->physBase - 0x800000000 + kCacheableView), gBootArgs->deviceTreeLength);

    gIOBase = dt_get_u64_prop_i("arm-io", "ranges", 1);

    map_full_ram(gBootArgs->physBase & 0x7ffffffff, gBootArgs->memSize);

    gDevType = dt_get_prop("arm-io", "device_type", NULL);
    size_t len = strlen(gDevType) - 3;
    len = len < 8 ? len : 8;
    strncpy(soc_name, gDevType, len);
    if  (strcmp(soc_name, "s5l8960x") == 0) socnum = 0x8960;
    else if(strcmp(soc_name, "t7000") == 0) socnum = 0x7000;
    else if(strcmp(soc_name, "t7001") == 0) socnum = 0x7001;
    else if(strcmp(soc_name, "s8001") == 0) socnum = 0x8001;
    else if(strcmp(soc_name, "t8010") == 0) socnum = 0x8010;
    else if(strcmp(soc_name, "t8011") == 0) socnum = 0x8011;
    else if(strcmp(soc_name, "t8012") == 0) socnum = 0x8012;
    else if(strcmp(soc_name, "t8015") == 0) socnum = 0x8015;
    else if(strcmp(soc_name, "s8000") == 0)
    {
        const char *sgx = dt_get_prop("sgx", "compatible", NULL);
        if(strlen(sgx) > 4 && strcmp(sgx + 4, "s8003") == 0)
        {
            socnum = 0x8003;
            soc_name[4] = '3';
        }
        else
        {
            socnum = 0x8000;
        }
    }

    // Do fuse init as early as possible
    fuse_init();

    // Setup GPIO Base
    gpio_early_init();

    // Setup serial pinmux
    serial_pinmux_init();

    // Enable serial TX
    serial_early_init();

    // Set up IRQ handling
    pongo_reinstall_vbar();

    task_alloc_fast_stacks(&sched_task);

    task_link(&sched_task);
    _task_set_current(&sched_task);

    // Setup VM
    vm_init();

    // Draw logo and set up framebuffer
    screen_init();

    // Set up main task for scheduling
    _REENT_INIT_PTR_ZEROED(&task_current()->reent);
    task_current()->vm_space = &kernel_vm_space;
    task_current()->cpsr = 0x205;
    task_current()->ttbr0 = kernel_vm_space.ttbr0;
    task_current()->ttbr1 = kernel_vm_space.ttbr1 | kernel_vm_space.asid;
    task_current()->proc = proc_create(NULL, "kernel", PROC_NO_VM);
    task_current()->proc->vm_space = &kernel_vm_space;

    void pongo_main_task();
    task_register(&pongo_task, pongo_main_task);

    // Set up FIQ timer
    preemption_over = 0;
    enable_interrupts();
    timer_init();
    timer_rearm();

    char has_been_preempted = 0;
    while (!gBootFlag) {
        char should_wfe = 0;
        char sched_ret = pongo_sched_tick();
        if (sched_ret == 2) {
            // we looped around the list
            if (has_been_preempted) {
                has_been_preempted = 0;
            } else {
                should_wfe = 1;
            }
        } else if (sched_ret == 1) {
            // we got preempted
            has_been_preempted = 1;
        } else if (sched_ret == 0) {
            // current task was not to be scheduled or we got volountarily yielded
        }
        if (should_wfe) {
            __asm__("wfe");
        }
    }

    // Release any potential sync USB listeners
    event_fire(&command_handler_iter);

    timer_disable();
    usb_teardown();
    disable_interrupts();
    preemption_over = 1;

    const char *boot_msg = NULL;

    switch(gBootFlag)
    {
        default: // >4
        case BOOT_FLAG_RAW: // 4
            break;

        case BOOT_FLAG_LINUX: // 3
            linux_prep_boot();
            boot_msg = "Booting Linux...";
            break;

        case BOOT_FLAG_HOOK: // 2
            // Hook for kernel patching here
            screen_puts("Invoking preboot hook");
            xnu_hook();
            // Fall through
        case BOOT_FLAG_HARD: // 1
        case BOOT_FLAG_DEFAULT: // 0
            // Boot XNU
            xnu_loadrd();
            if (sep_boot_hook)
                sep_boot_hook();
            boot_msg = "Booting";
            break;
    }

    sep_teardown();

    // Flush changes to IORVBAR and the AES engine to recfg as late as possible.
    // If SEP needs this earlier, then the code in sep.c will make the necessary calls.
    // This should also be fine in all configs, since this doesn't lock anything.
    recfg_soc_sync();

    // Should happen after recfg stuff
    serial_teardown();
    // No [i]printf from here on out, only screen_puts

    // We want this in all configs, and it must only happen once we no longer need serial
    interrupt_teardown();

    __asm__ volatile("dsb sy");
    if(boot_msg)
        screen_puts(boot_msg);
    else
        screen_fill_basecolor();
}

/*

    Name: pongo_entry
    Description: entry point in llktrw

*/
extern void set_exception_stack_core0();
extern void lowlevel_set_identity(void);
extern _Noreturn void jump_to_image_extended(uint64_t image, uint64_t args, uint64_t tramp, uint64_t original_image);
extern uint64_t gPongoSlide;

_Noreturn void pongo_entry(uint64_t *kernel_args, void *entryp, void (*exit_to_el1_image)(void *boot_args, void *boot_entry_point, void *trampoline))
{
    gBootArgs = (boot_args*)kernel_args;
    gTopOfKernelData = gBootArgs->topOfKernelData;
    gEntryPoint = entryp;
    lowlevel_setup(gBootArgs->physBase & 0x7ffffffff, gBootArgs->memSize);
    rebase_pc(gPongoSlide);
    set_exception_stack_core0();
    pongo_entry_cached();
    lowlevel_set_identity();
    rebase_pc(-gPongoSlide);
    set_exception_stack_core0();
    gFramebuffer = (uint32_t*)gBootArgs->Video.v_baseAddr;
    lowlevel_cleanup();
    if(gBootFlag == BOOT_FLAG_RAW)
    {
        // We're in EL1 here, but we might need to go back to EL3
        uint64_t pfr0;
        __asm__ volatile("mrs %0, id_aa64pfr0_el1" : "=r"(pfr0));
        if((pfr0 & 0xf000) != 0)
        {
            __asm__ volatile("smc 0"); // elevate to EL3
        }
        // XXX: We should really replace loader_xfer_recv_data with something dedicated here.
        jump_to_image_extended(((uint64_t)loader_xfer_recv_data) - kCacheableView + 0x800000000, (uint64_t)gBootArgs, 0, (uint64_t)gEntryPoint);
    }
    else
    {
        if(gBootFlag == BOOT_FLAG_LINUX)
        {
            linux_boot();
        }
        else
        {
            xnu_boot();
        }
        exit_to_el1_image(gBootArgs, gEntryPoint, (void*)((gTopOfKernelData + 0x3fffULL) & ~0x3fffULL));
    }
    screen_puts("didn't boot?!");
    while(1)
    {}
}
