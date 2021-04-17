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
uint64_t gInterruptBase;
uint64_t gPMGRBase;
uint64_t gWDTBase;

__asm__(
    ".globl _get_el\n"
    ".globl _rebase_pc\n"
    ".globl _set_vbar_el1\n"
    ".globl __enable_interrupts\n"
    ".globl __disable_interrupts\n"
    ".globl _get_mpidr\n"
    ".globl _get_migsts\n"
    ".globl _set_migsts\n"
    ".globl _get_mmfr0\n"
    ".globl _invalidate_icache\n"
    ".globl _enable_mmu_el1\n"
    ".globl _disable_mmu_el1\n"
    ".globl _get_ticks\n"
    ".globl _panic_new_fp\n"
    ".globl _copy_safe_internal\n"
    ".globl _copy_retn\n"
    ".globl _pan_on\n"
    ".globl _pan_off\n"

    "_get_el:\n"
    "    mrs x0, currentel\n"
    "    lsr x0, x0, 2\n"
    "    ret\n"
    "_rebase_pc:\n"
    "    add sp, sp, x0\n"
    "    add x29, x29, x0\n"
    "    add x30, x30, x0\n"
    "    ret\n"

    "_set_vbar_el1:\n"
    "    msr vbar_el1, x0\n"
    "    isb\n"
    "    ret\n"

    "__enable_interrupts:\n"
    "    msr daifclr,#0xf\n"
    "    isb\n"
    "    ret\n"
    "__disable_interrupts:\n"
    "    msr daifset,#0xf\n"
    "    isb\n"
    "    ret\n"

    "_get_mpidr:\n"
    "    mrs x0, MPIDR_EL1\n"
    "    ret\n"
    "_get_migsts:\n"
    "    mrs x0, S3_4_c15_c0_4\n"
    "    ret\n"
    "_set_migsts:\n"
    "    msr S3_4_c15_c0_4, x0\n"
    "    ret\n"
    "_get_mmfr0:\n"
    "    mrs x0, id_aa64mmfr0_el1\n"
    "    ret\n"
    "_invalidate_icache:\n"
    "    dsb ish\n"
    "    ic iallu\n"
    "    dsb ish\n"
    "    isb\n"
    "    ret\n"

    "_enable_mmu_el1:\n"
    "    dsb sy\n"
    "    msr mair_el1, x2\n"
    "    msr tcr_el1, x1\n"
    "    msr ttbr0_el1, x0\n"
    "    msr ttbr1_el1, x3\n"
    "    isb sy\n"
    "    tlbi vmalle1\n"
    "    isb sy\n"
    "    ic iallu\n"
    "    isb sy\n"
    "    mrs x3, sctlr_el1\n"
    "    orr x3, x3, #1\n"
    "    orr x3, x3, #4\n"
    "    orr x3, x3, #0x800000\n" // enable SPAN if possible
    "    and x3, x3, #(~2)\n"
    "    msr sctlr_el1, x3\n"
    "    ic iallu\n"
    "    dsb sy\n"
    "    isb sy\n"
    "    ret\n"

    "_disable_mmu_el1:\n"
    "    dsb sy\n"
    "    isb sy\n"
    "    mrs x3, sctlr_el1\n"
    "    and x3, x3, #(~1)\n"
    "    and x3, x3, #(~4)\n"
    "    msr sctlr_el1, x3\n"
    "    tlbi vmalle1\n"
    "    ic iallu\n"
    "    dsb sy\n"
    "    isb sy\n"
    "    ret\n"

    "_get_ticks:\n"
    "    isb sy\n"
    "    mrs x0, cntpct_el0\n"
    "    ret\n"
    "_pan_on:\n"
    ".long 0xd500419f\n"
    "    ret\n"
    "_pan_off:\n"
    ".long 0xd500409f\n"
    "    ret\n"

    "_panic_new_fp:\n"
    "    mov x29, 0\n"
    "    b _panic\n"
    "_copy_trap_internal:\n"
    "    stp x29, x30, [sp, -0x10]!\n"
    "    mov x4, xzr\n"
    "    1:\n"
    "    cbz x2, 2f\n"
    "    ldrb w5, [x1], #1\n"
    "    strb w5, [x0], #1\n"
    "    sub x2, x2, #1\n"
    "    add x4, x4, #1\n"
    "    b 1b\n"
    "2:\n"
    "_copy_retn:\n"
    "    mov x0, x4\n"
    "    ldp x29, x30, [sp], 0x10\n"
    "    ret\n"
    );
extern void copy_retn(void);
extern size_t copy_trap_internal(void* dest, void* src, size_t size);
uint64_t exception_stack[0x4000/8] = {1};
uint64_t sched_stack[0x4000/8] = {1};
size_t memcpy_trap(void* dest, void* src, size_t size) {
    disable_interrupts();
    if (!task_current()) panic("memcpy_trap requires task_current() to be populated");
    if (task_current()->fault_catch) panic("memcpy_trap called with fault hook already populated");
    task_current()->fault_catch = copy_retn;
    uint64_t ID_MMFR3_EL1;
    asm volatile("mrs %0, ID_MMFR3_EL1" : "=r"(ID_MMFR3_EL1));

    if (ID_MMFR3_EL1 & 0xF0000) // PAN exists!
    {
        extern volatile void pan_off();
        pan_off();
    }
    size_t retn = copy_trap_internal(dest, src, size);
    if (ID_MMFR3_EL1 & 0xF0000) // PAN exists!
    {
        extern volatile void pan_on();
        pan_on();
    }

    task_current()->fault_catch = NULL;
    enable_interrupts();
    return retn;
}

extern _Noreturn void panic_new_fp(const char* string, ...);

uint64_t dis_int_count = 1;
void _enable_interrupts();
void enable_interrupts() {
    if (!dis_int_count) panic("irq over-enable");
    dis_int_count--;
    if (!dis_int_count) {
        _enable_interrupts();
    }
}
void enable_interrupts_asserted() {
    if (!dis_int_count) panic("irq over-enable");
    dis_int_count--;
}
void _disable_interrupts();
void disable_interrupts() {
    _disable_interrupts();
    dis_int_count++;
    if (!dis_int_count) panic("irq over-disable");
}

volatile char is_in_exception;

void print_state(uint64_t* state) {
    task_critical_enter();
    for (int i=0; i<31; i++) {
        fiprintf(stderr, "X%d: %s0x%016llx ", i, i < 10 ? " " : "", state[i]);
        if (i == 30) break;
        if ((i & 1) == 1) {
            if ((i & 3) == 3) {
                putc('\n', stderr);
            } else {
                fflush(stderr);
                screen_putc('\n'); // avoid word wrap on screen
            }
        }
    }
    fiprintf(stderr, "SP:  0x%016llx\n", state[0x118/8]);
    fiprintf(stderr, "ESR: 0x%016llx ", state[0xf8/8]);
    fiprintf(stderr, "ELR: 0x%016llx ", state[0x100/8]);
    fflush(stderr);
    screen_putc('\n'); // avoid word wrap on screen
    fiprintf(stderr, "FAR: 0x%016llx ", state[0x108/8]);
    fiprintf(stderr, "CPSR:        0x%08llx\n", state[0x110/8]);

    struct task *t = task_current();
    if (!t) {
        fiprintf(stderr, "skipping call stack due task_current() == NULL\n");
    } else if (t->critical_count > 1) {
        fiprintf(stderr, "skipping call stack due to fault in critical section\n");
    } else {
        fiprintf(stderr, "Call stack:\n");
        fiprintf(stderr, "         registers: fp 0x%016llx, lr 0x%016llx\n", state[29], state[30]);
        int depth = 0;
        uint64_t fpcopy[2];
        for(uint64_t *fp = (uint64_t*)state[29]; fp; fp = (uint64_t*)fpcopy[0])
        {
            if (memcpy_trap(fpcopy, fp, 0x10) == 0x10) {
                fiprintf(stderr, "0x%016llx: fp 0x%016llx, lr 0x%016llx\n", ((uint64_t)fp), fpcopy[0], fpcopy[1]);
            } else {
                fiprintf(stderr, "couldn't access frame at %016llx, stopping here..,\n", (uint64_t)fp);
                break;
            }
            depth++;
            if (depth > 64) {
                fiprintf(stderr, "stack depth too large, stopping here...\n");
                break;
            }
        }
    }
    fflush(stderr);
    task_critical_exit();
}
int sync_exc_handle(uint64_t* state) {
    struct task *t = task_current();
    uint64_t far = state[0x108/8];
    uint64_t esr = state[0xf8/8];
    uint64_t esr_ec = (esr & 0xFC000000) >> 26;

    if (t && ((esr_ec == 0b100101) || // Data abort from current EL
              (esr_ec == 0b100100)    // Data abort from lower EL
              )) {
        if (vm_fault(t->vm_space, far, PROT_READ | (esr_ec & 0b1 ? PROT_KERN_ONLY : 0))) {
            return 0;
        }
    }
    if (t && ((esr_ec == 0b100000) || // Instruction abort from lower EL
              (esr_ec == 0b100001)    // Instruction abort from current EL
              )) {
        if (vm_fault(t->vm_space, far, PROT_EXEC | (esr_ec & 0b1 ? PROT_KERN_ONLY : 0))) {
            return 0;
        }
    }

    if (t && t->fault_catch) {
        // fiprintf(stderr, "caught fault with fault_catch, overwriting lr\n");
        state[0x100/8] = (uint64_t)t->fault_catch;
        t->fault_catch = NULL; // do not support double faults here
        return 0;
    }
    return 1;
}
int sync_exc(uint64_t* state) {
    _disable_interrupts();
    dis_int_count++;
    if (!task_current()) panic("caught sync exception with task_current() == NULL");

    if (!sync_exc_handle(state)) {
        dis_int_count --;
        return 0;
    }

    if (dis_int_count != 1) {
        print_state(state);
        panic("caught sync exception with interrupts held");
    }
    print_state(state);
    task_crash_asserted("caught sync exception!");
    dis_int_count = 0;
    return 0;
}
int sync_exc_el0(uint64_t* state) {
    _disable_interrupts();
    dis_int_count++;

    if (dis_int_count != 1) {
        print_state(state);
        panic("caught EL0 exception with km interrupts held?!");
    }

    uint64_t esr = state[0xf8/8];
    if (!(esr & 0x2000000)) panic("sync_exc_el0 from A32 EL0 is unsupported");

    uint64_t esr_ec = esr & 0xFC000000;
    if (esr_ec == 0x54000000) {
        pongo_syscall_entry(task_current(), (esr & 0xff), state);
        if (dis_int_count != 1) {
            panic("pongo_syscall_entry returned with disable_interrupt count != 1");
        }
        dis_int_count = 0;
        return 0;
    }

    dis_int_count = 0;
    return sync_exc(state);
}
uint32_t interrupt_vector() {
    return (*(volatile uint32_t *)(gInterruptBase + 0x2004));
}
uint64_t interruptCount = 0, fiqCount = 0;
uint32_t do_preempt = 1;
void disable_preemption() {
    disable_interrupts();
    do_preempt++;
    enable_interrupts();
}
void enable_preemption() {
    disable_interrupts();
    do_preempt--;
    enable_interrupts();
}
int irq_exc() {
    timer_disable();
    dis_int_count = 1;
    is_in_exception = 1;
    interruptCount++;
    if (task_current()->irq_ret) {
        panic("nested IRQs are not supported at this time");
    }
    uint32_t intr = interrupt_vector();
    while (intr) {
        task_irq_dispatch(intr);
        intr = interrupt_vector();
    }
    if (dis_int_count != 1) panic("IRQ handler left interrupts disabled...");
    is_in_exception = 0;
    dis_int_count = 0;
    timer_enable();
    return 0;
}
int serror_exc(uint64_t* state) {
    is_in_exception = 1;
    dis_int_count = 1;
    print_state(state);
    panic_new_fp("caught serror exception");
    is_in_exception = 0;
    return 0;
}
int _fiq_exc() {
    is_in_exception = 1;
    fiqCount++;
    dis_int_count = 1;
    wdt_enable();
    int ret_val = pongo_fiq_handler();
    if (dis_int_count != 1) panic("FIQ handler left interrupts disabled...");
    dis_int_count = 0;
    is_in_exception = 0;
    return ret_val;
}
extern uint64_t preemption_counter;
int fiq_exc() {
    int fiq_r = _fiq_exc();
    if (fiq_r) {
        preemption_counter++;
    }
    return fiq_r;
}
void fiq_sp1() {
    panic("got FIQ in EL1h SP1?!");
}
void irq_sp1() {
    panic("got FIQ in EL1h SP1?!");
}
void spin(uint32_t usec)
{
    disable_interrupts();
    uint64_t eta_now = get_ticks();
    uint64_t eta_wen = eta_now + (24*usec);
    while (1) {
        asm volatile("isb");
        uint64_t curtime = get_ticks();
        if (eta_now > curtime)
            break;
        if (curtime > eta_wen)
            break;
    }
    enable_interrupts();
}
void usleep(uint64_t usec)
{
    disable_interrupts();
    uint64_t eta_wen = get_ticks() + (24*usec);
    uint64_t preempt_after = get_ticks() + 2400;
    task_current()->wait_until = eta_wen;
    enable_interrupts();
    while (1) {
        uint64_t curtime = get_ticks();
        if (curtime > eta_wen)
            break;
        if (curtime > preempt_after)
            task_yield();
    }
}
void sleep(uint32_t sec)
{
    usleep((uint64_t)sec * 1000000ULL);
}
int gAICVersion = -1;
int gAICStyle = -1;

__attribute__((used)) static void interrupt_or_config(uint32_t bits) {
    *(volatile uint32_t*)(gInterruptBase + 0x10) |= bits;
}
__attribute__((used)) static void interrupt_and_config(uint32_t bits) {
    *(volatile uint32_t*)(gInterruptBase + 0x10) &= bits;
}
uint32_t interrupt_masking_base = 0;
void unmask_interrupt(uint32_t reg) {
    (*(volatile uint32_t *)(gInterruptBase + 0x4180 + ((reg >> 5) * 4))) = (1 << ((reg) & 0x1F));

}
void mask_interrupt(uint32_t reg) {
    (*(volatile uint32_t *)(gInterruptBase + 0x4100 + ((reg >> 5) * 4))) = (1 << ((reg) & 0x1F));
}

#define WDT_CHIP_TMR (*(volatile uint32_t*)(gWDTBase + 0x0))
#define WDT_CHIP_RST (*(volatile uint32_t*)(gWDTBase + 0x4))
#define WDT_CHIP_INT (*(volatile uint32_t*)(gWDTBase + 0x8))
#define WDT_CHIP_CTL (*(volatile uint32_t*)(gWDTBase + 0xc))

#define WDT_SYS_TMR (*(volatile uint32_t*)(gWDTBase + 0x10))
#define WDT_SYS_RST (*(volatile uint32_t*)(gWDTBase + 0x14))
#define WDT_SYS_CTL (*(volatile uint32_t*)(gWDTBase + 0x1c))

void wdt_reset()
{
    if(!gWDTBase)
    {
        fiprintf(stderr, "wdt is not set up but was asked to reset, spinning here");
    }
    else
    {
        WDT_CHIP_CTL = 0x0; // Disable WDT
        WDT_SYS_CTL  = 0x0; // Disable WDT
        WDT_SYS_RST  = 1; // Immediate reset
        WDT_SYS_CTL  = 0x4; // Enable WDT
        WDT_SYS_TMR  = 0; // Reset counter
    }
    panic("wdt reset");
}
void wdt_enable()
{
    // TODO: We should probably change this func signature to include a timeout, if we actually plan to use it?
    return;
#if 0
    if (!gWDTBase) return;
    *(volatile uint32_t*)(gWDTBase + 0xc) = 0;
    *(volatile uint32_t*)(gWDTBase + 0x4) = 5 * 24000000; // fire watchdog reset every 5 seconds
    *(volatile uint32_t*)(gWDTBase + 0x0) = 0x80000000;
    *(volatile uint32_t*)(gWDTBase + 0xc) = 4;
    *(volatile uint32_t*)(gWDTBase + 0x0) = 0;
#endif
}
void wdt_disable()
{
    if (!gWDTBase) return;
    WDT_CHIP_CTL = 0x0; // Disable WDT
    WDT_SYS_CTL  = 0x0; // Disable WDT
}

typedef struct
{
    uint64_t addr;
    uint64_t size;
} pmgr_reg_t;

typedef struct
{
    uint32_t reg;
    uint32_t off;
    uint32_t idk;
} pmgr_map_t;

typedef struct
{
    uint32_t flg : 8,
             a   : 16,
             id  : 8;
    uint32_t b;
    uint32_t c   : 16,
             idx :  8,
             map :  8;
    uint32_t d;
    uint32_t e;
    uint32_t f;
    uint32_t g;
    uint32_t h;
    char name[0x10];
} pmgr_dev_t;

static uint32_t gPMGRreglen = 0;
static uint32_t gPMGRmaplen = 0;
static uint32_t gPMGRdevlen = 0;
static pmgr_reg_t *gPMGRreg = NULL;
static pmgr_map_t *gPMGRmap = NULL;
static pmgr_dev_t *gPMGRdev = NULL;

void pmgr_init()
{
    dt_node_t *pmgr = dt_find(gDeviceTree, "pmgr");
    gPMGRreg = dt_prop(pmgr, "reg",     &gPMGRreglen);
    gPMGRmap = dt_prop(pmgr, "ps-regs", &gPMGRmaplen);
    gPMGRdev = dt_prop(pmgr, "devices", &gPMGRdevlen);
    gPMGRreglen /= sizeof(*gPMGRreg);
    gPMGRmaplen /= sizeof(*gPMGRmap);
    gPMGRdevlen /= sizeof(*gPMGRdev);
    gPMGRBase = gIOBase + gPMGRreg[0].addr;
    gWDTBase  = gIOBase + dt_get_u64_prop("wdt", "reg");
    command_register("reset", "resets the device", wdt_reset);
    command_register("crash", "branches to an invalid address", (void*)0x41414141);
}
void interrupt_init() {
    gInterruptBase = dt_get_u32_prop("aic", "reg");
    gInterruptBase += gIOBase;

    gAICVersion = dt_get_u32_prop("aic", "aic-version");

    interrupt_or_config(0xE0000000);
    interrupt_or_config(1); // enable interrupt
}
void interrupt_teardown() {
    wdt_disable();
    task_irq_teardown();
}

uint64_t device_clock_by_id(uint32_t id)
{
    for(uint32_t i = 0; i < gPMGRdevlen; ++i)
    {
        pmgr_dev_t *d = &gPMGRdev[i];
        if(d->id != id)
        {
            continue;
        }
        if((d->flg & 0x10) || d->map >= gPMGRmaplen)
        {
            break;
        }
        pmgr_map_t *m = &gPMGRmap[d->map];
        pmgr_reg_t *r = &gPMGRreg[m->reg];
        if(d->idx >= ((r->size - m->off) >> 3))
        {
            break;
        }
        return gIOBase + r->addr + m->off + (d->idx << 3);
    }
    return 0;
}

uint64_t device_clock_by_name(const char *name)
{
    for(uint32_t i = 0; i < gPMGRdevlen; ++i)
    {
        pmgr_dev_t *d = &gPMGRdev[i];
        if(strncmp(name, d->name, sizeof(d->name)) != 0)
        {
            continue;
        }
        if((d->flg & 0x10) || d->map >= gPMGRmaplen)
        {
            break;
        }
        pmgr_map_t *m = &gPMGRmap[d->map];
        pmgr_reg_t *r = &gPMGRreg[m->reg];
        if(d->idx >= ((r->size - m->off) >> 3))
        {
            break;
        }
        return gIOBase + r->addr + m->off + (d->idx << 3);
    }
    return 0;
}

void clock_gate(uint64_t addr, char val)
{
    if (val) {
        *(volatile uint32_t*)(addr) |= 0xF;
    } else {
        *(volatile uint32_t*)(addr) &= ~0xF;
    }

    while (1) {
        uint32_t x = *(volatile uint32_t*)(addr);
        if((x & 0xf) == ((x >> 4) & 0xf)) break;
    }
}

void
cache_invalidate(void *address, size_t size) {
    uint64_t cache_line_size = 64;
    uint64_t start = ((uintptr_t) address) & ~(cache_line_size - 1);
    uint64_t end = ((uintptr_t) address + size + cache_line_size - 1) & ~(cache_line_size - 1);
    asm volatile("isb");
    asm volatile("dsb sy");
    for (uint64_t addr = start; addr < end; addr += cache_line_size) {
        asm volatile("dc ivac, %0" : : "r"(addr));
    }
    asm volatile("dsb sy");
    asm volatile("isb");
}

void
cache_clean_and_invalidate(void *address, size_t size) {
    uint64_t cache_line_size = 64;
    uint64_t start = ((uintptr_t) address) & ~(cache_line_size - 1);
    uint64_t end = ((uintptr_t) address + size + cache_line_size - 1) & ~(cache_line_size - 1);
    asm volatile("isb");
    asm volatile("dsb sy");
    for (uint64_t addr = start; addr < end; addr += cache_line_size) {
        asm volatile("dc civac, %0" : : "r"(addr));
    }
    asm volatile("dsb sy");
    asm volatile("isb");
}

void
cache_clean(void *address, size_t size) { // invalidates too, because Apple
    uint64_t cache_line_size = 64;
    uint64_t start = ((uintptr_t) address) & ~(cache_line_size - 1);
    uint64_t end = ((uintptr_t) address + size + cache_line_size - 1) & ~(cache_line_size - 1);
    asm volatile("isb");
    asm volatile("dsb sy");
    for (uint64_t addr = start; addr < end; addr += cache_line_size) {
        asm volatile("dc civac, %0" : : "r"(addr));
    }
    asm volatile("dsb sy");
    asm volatile("isb");
}
extern uint64_t heap_base;
extern uint64_t heap_end;
extern uint64_t linear_kvm_base;
extern uint64_t linear_kvm_end;
uint64_t vatophys_force(uint64_t kvaddr) {
    uint64_t par_el1;
    disable_interrupts();
    asm volatile("at s1e1r, %0" : : "r"(kvaddr));
    asm volatile("isb");
    asm volatile("mrs %0, par_el1" : "=r"(par_el1));
    enable_interrupts();
    if (par_el1 & 0x1) {
        return -1;
    }
    par_el1 &= 0xFFFFFFFFFFFF;
    if (is_16k()) {
        return (kvaddr & 0x3fffULL) | (par_el1 & (~0x3fffULL));
    } else {
        return (kvaddr & 0xfffULL) | (par_el1 & (~0xfffULL));
    }
}
uint64_t vatophys(uint64_t kvaddr) {
    if(kvaddr >= 0x8000000000000000) {
        panic("vatophys: address must be in ttbr0");
    } else if (kvaddr >= heap_base && kvaddr < heap_end) {
        panic("vatophys: called on heap, which is non-contiguous!");
    } else if (kvaddr >= linear_kvm_base && kvaddr < linear_kvm_end) {
        panic("vatophys: called on kvm, which is non-contiguous!");
    }
    return vatophys_force(kvaddr);
}
