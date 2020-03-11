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

boot_args * gBootArgs;
void* gEntryPoint;

#define BOOT_FLAG_DEFAULT 0
#define BOOT_FLAG_HARD 1
#define BOOT_FLAG_HOOK 2
#define BOOT_FLAG_LINUX 3
#define BOOT_FLAG_RAW 4

volatile char gBootFlag = 0;
dt_node_t *gDeviceTree;
uint64_t gIOBase;
char* gDevType;
uint64_t gESTS;
void (*preboot_hook)();
void (*rdload_hook)();

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
    if (get_el() == 1) {
        set_vbar_el1((uint64_t)&exception_vector);
    } else {
        set_vbar_el3((uint64_t)&exception_vector);
    }
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
        struct task* tsk = pongo_sched_head;
        pongo_sched_head = pongo_sched_head->next;
        if (tsk->flags & TASK_LINKED) {
            _task_switch_asserted(tsk);
            disable_interrupts();
            if (preempt_ctr) {
                rvalue = 1;
                preempt_ctr = 0;
            }
        } else if (tsk->flags & TASK_HAS_CRASHED) {
            if (tsk->crash_callback) tsk->crash_callback();
            tsk->flags &= ~TASK_HAS_CRASHED;
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

__attribute__((noinline)) void pongo_entry_cached() {
    gDeviceTree = (void*)((uint64_t)gBootArgs->deviceTreeP - gBootArgs->virtBase + gBootArgs->physBase - 0x800000000 + kCacheableView);
    gIOBase = dt_get_u64_prop_i("arm-io", "ranges", 1);
    uint64_t max_video_addr = gBootArgs->Video.v_baseAddr + gBootArgs->Video.v_rowBytes * gBootArgs->Video.v_height;
    uint64_t max_mem_size = max_video_addr - 0x800000000;
    if (gBootArgs->memSize > max_mem_size) max_mem_size = gBootArgs->memSize;
    map_full_ram(0, max_mem_size);

    extern int socnum;
    gDevType = dt_get_prop("arm-io", "device_type", NULL);
    size_t len = strlen(gDevType) - 3;
    char soc_name[9] = {};
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
    
    /*
        Set up IRQ handling
    */

    pongo_reinstall_vbar();
    enable_interrupts();

    /*
        Draw logo and set up framebuffer
    */

    screen_init();

    /*
        Set up main task for scheduling
    */
    void pongo_main_task();
    task_register(&pongo_task, pongo_main_task);
    task_link(&pongo_task);

    /*
        Set up FIQ timer
    */

    extern void _task_set_current(struct task* t);

    task_link(&sched_task);
    _task_set_current(&sched_task);

    timer_init();
    timer_rearm();

    extern void _task_switch_asserted(struct task* new);

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
    timer_disable();
    disable_interrupts();

    while (gBootFlag)
    {
        if (gBootFlag == BOOT_FLAG_RAW) {
            screen_fill_basecolor();
            return;
        }
        if (gBootFlag == BOOT_FLAG_LINUX) {
            screen_puts("Booting Linux...");
            return linux_prep_boot();
        }
        if (gBootFlag == BOOT_FLAG_HOOK && preboot_hook) {
            // hook for kernel patching here
            screen_puts("Invoking preboot hook");
            preboot_hook();
        }
        gBootFlag--;
    }

    if (rdload_hook) rdload_hook();
    screen_puts("Booting");
}

/*

    Name: pongo_entry
    Description: entry point in llktrw

*/
volatile void jump_to_image_extended(uint64_t image, uint64_t args, uint64_t original_image);

void pongo_entry(uint64_t *kernel_args, void *entryp, void (*exit_to_el1_image)(void *boot_args, void *boot_entry_point))
{
    gBootArgs = (boot_args*)kernel_args;
    gEntryPoint = entryp;
    lowlevel_setup(0, 0x30000000);
    rebase_pc(kCacheableView - 0x800000000);
    pongo_entry_cached();
    gFramebuffer = (uint32_t*)gBootArgs->Video.v_baseAddr;
    rebase_pc(0x800000000 - kCacheableView);
    lowlevel_cleanup();
    if(gBootFlag == BOOT_FLAG_RAW)
    {
        jump_to_image_extended(((uint64_t)loader_xfer_recv_data) - kCacheableView + 0x800000000, (uint64_t)gBootArgs, (uint64_t)gEntryPoint);
    }
    else if(gBootFlag == BOOT_FLAG_LINUX)
    {
        linux_boot();
        exit_to_el1_image((void*)gBootArgs, gEntryPoint);
    }
    else
    {
        exit_to_el1_image((void*)gBootArgs, gEntryPoint);
    }
    screen_puts("didn't boot?!");
    while(1)
    {}
}
