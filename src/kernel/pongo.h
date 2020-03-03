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

#include <mach-o/loader.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#include "framebuffer/fb.h"
#include "usb/usb.h"
#include "uart/uart.h"
#include "gpio/gpio.h"
#include "timer/timer.h"

#define DT_KEY_LEN 0x20

struct Boot_Video {
	unsigned long	v_baseAddr;	/* Base address of video memory */
	unsigned long	v_display;	/* Display Code (if Applicable */
	unsigned long	v_rowBytes;	/* Number of bytes per pixel row */
	unsigned long	v_width;	/* Width */
	unsigned long	v_height;	/* Height */
	unsigned long	v_depth;	/* Pixel Depth and other parameters */
};
typedef struct boot_args {
	uint16_t		Revision;			/* Revision of boot_args structure */
	uint16_t		Version;			/* Version of boot_args structure */
	uint64_t		virtBase;			/* Virtual base of memory */
	uint64_t		physBase;			/* Physical base of memory */
	uint64_t		memSize;			/* Size of memory */
	uint64_t		topOfKernelData;	/* Highest physical address used in kernel data area */
	struct Boot_Video Video;				/* Video Information */
	uint32_t		machineType;		/* Machine Type */
	void			*deviceTreeP;		/* Base of flattened device tree */
	uint32_t		deviceTreeLength;	/* Length of flattened tree */
	char			CommandLine[256];	/* Passed in command line */
	uint64_t		bootFlags;		/* Additional flags specified by the bootloader */
	uint64_t		memSizeActual;		/* Actual size of memory */
} boot_args;

typedef struct
{
    uint32_t nprop;
    uint32_t nchld;
    char prop[];
} dt_node_t;

typedef struct
{
    char key[DT_KEY_LEN];
    uint32_t len;
    char val[];
} dt_prop_t;

typedef struct
{
    const char* name;
    dt_node_t* node;
} dt_find_cb_t;

typedef struct
{
    const char* key;
    void* val;
    uint32_t len;
} dt_prop_cb_t;
struct memmap {
    uint64_t addr;
    uint64_t size;
};

typedef uint64_t lock;
extern void lock_take(lock* lock); // takes a lock spinning initially but after being pre-empted once it will start yielding until it acquires it
extern void lock_take_spin(lock* lock); // takes a lock spinning until it acquires it
extern void lock_release(lock* lock); // releases ownership on a lock

extern int dt_check(void* mem, uint32_t size, uint32_t* offp);
extern int dt_parse(dt_node_t* node, int depth, uint32_t* offp, int (*cb_node)(void*, dt_node_t*), void* cbn_arg, int (*cb_prop)(void*, dt_node_t*, int, const char*, void*, uint32_t), void* cbp_arg);
extern dt_node_t* dt_find(dt_node_t* node, const char* name);
extern void* dt_prop(dt_node_t* node, const char* key, uint32_t* lenp);
extern void* dt_get_prop(const char* device, const char* prop, uint32_t* size);
extern struct memmap* dt_alloc_memmap(dt_node_t* node, const char* name);
extern void task_yield_asserted();
extern void _task_yield();
extern uint8_t * loader_xfer_recv_data;
extern uint32_t loader_xfer_recv_count;
extern uint32_t autoboot_count;

#define TASK_CAN_CRASH 1
#define TASK_LINKED 2
#define TASK_IRQ_HANDLER 4
#define TASK_PREEMPT 8
#define TASK_MASK_NEXT_IRQ 16
#define TASK_HAS_EXITED 32
#define TASK_WAS_LINKED 64
#define TASK_HAS_CRASHED 128
struct event {
	struct task* task_head;
};

struct task {
    uint64_t x[30];
    uint64_t lr;
    uint64_t sp;
    uint64_t runcnt;
    uint64_t real_lr;
    uint64_t fp[18];
    struct task* irq_ret;
    uint64_t entry;
    void* task_ctx;
    uint64_t stack[0x2000 / 8];
    uint64_t irq_count;
    uint32_t irq_type;
    uint64_t wait_until;
    uint32_t sched_count;
    uint32_t pid;
    struct task* eq_next;
    uint64_t anchor[0];
    uint64_t t_flags; // task-specific flags, not used by task subsystem if not for internal tasks
    char name[32];
    uint32_t flags;
    struct task* next;
    struct task* prev;
    void (*crash_callback)();
};
extern boot_args * gBootArgs;
extern void* gEntryPoint;
extern dt_node_t *gDeviceTree;
extern uint64_t gIOBase;
extern uint64_t gPMGRBase;
extern char* gDevType;
extern void* ramdisk_buf;
extern uint32_t ramdisk_size;

#define kCacheableView 0x400000000ULL
#define MAGIC_BASE 0x828000000ULL
struct pongo_exports {
    const char* name;
    void * value;
};
#define EXPORT_SYMBOL(x) {.name = ""#x, .value = x}
#define EXPORT_SYMBOL_P(x) {.name = ""#x, .value = (void*)&x}

void pongo_entry(uint64_t* kernel_args, void* entryp, void (*exit_to_el1_image)(void* boot_args, void* boot_entry_point));
int pongo_fiq_handler();
extern void (*preboot_hook)();
extern void (*rdload_hook)();
extern void task_register_coop(struct task* task, void (*entry)()); // registers a cooperative task
extern void task_register_preempt_irq(struct task* task, void (*entry)(), int irq_id); // registers an irq handler
extern void task_register_irq(struct task* task, void (*entry)(), int irq_id); // registers an irq handler
extern void task_register(struct task* task, void (*entry)()); // register a preempt task
extern void task_yield();
extern void task_wait();
extern void task_exit();
extern void event_wait_asserted(struct event* ev);
extern void event_wait(struct event* ev);
extern void event_fire(struct event* ev);
extern void* alloc_static(uint32_t size); // memory returned by this will be added to the xnu static region, thus will persist after xnu boot

extern struct event command_handler_iter;


extern void* memset(void *b, int c, size_t len);
extern void* memmem(const void* big, unsigned long blength, const void* little, unsigned long llength);
extern void* memstr(const void* big, unsigned long blength, const char* little);
extern void* memstr_partial(const void* big, unsigned long blength, const char* little);

extern uint64_t scheduler_ticks;
extern void print_register(uint64_t value);
void print_hex_number(uint64_t value);
extern volatile void invalidate_icache();
extern struct task* task_current();
extern char preemption_should_skip_beat();
extern void task_switch_irq(struct task* to_task);
extern void task_exit_irq();
extern void task_switch(struct task* to_task);
extern void task_link(struct task* to_task);
extern void task_unlink(struct task* to_task);
extern void task_irq_dispatch(uint32_t intr);
extern void task_yield_asserted();
extern void task_register_unlinked(struct task* task, void (*entry)());
extern void task_suspend_self();
extern void panic(const char* string);
extern void pmgr_reset();
extern void spin(uint32_t usec);
extern void task_set_sched_head(struct task* task);
extern void enable_interrupts();
extern void disable_interrupts();
extern uint64_t get_ticks();
extern void usleep(uint32_t usec);
extern void sleep(uint32_t sec);
extern uint32_t dt_get_u32_prop(const char* device, const char* prop);
extern uint64_t dt_get_u64_prop(const char* device, const char* prop);
extern uint64_t dt_get_u64_prop_i(const char* device, const char* prop, uint32_t idx);
extern void unmask_interrupt(uint32_t reg);
extern void mask_interrupt(uint32_t reg);
extern void wdt_reset();
extern void wdt_enable();
extern void wdt_disable();
extern bool linux_can_boot();
extern void linux_prep_boot();
extern void linux_boot();
extern void command_in_char(char val);
extern void command_putc(char val);
extern void command_puts(const char* val);
extern void command_print(const char* val);
extern void command_register(const char* name, const char* desc, void (*cb)(const char* cmd, char* args));
extern char* command_tokenize(char* str, uint32_t strbufsz);
extern volatile uint8_t get_el(void);
#define STDOUT_BUFLEN 512
extern void fetch_stdoutbuf(char* to, int* len);
extern uint64_t vatophys(uint64_t kvaddr);
extern void cache_invalidate(void *address, size_t size);
extern void cache_clean_and_invalidate(void *address, size_t size);
extern void cache_clean(void *address, size_t size);
extern void register_irq_handler(uint16_t irq_v, struct task* irq_handler);
extern void clock_gate(uint64_t addr, char val);
extern void disable_preemption();
extern void enable_preemption();
extern void* alloc_contig(uint32_t size);
extern void task_suspend_self_asserted();
extern void command_execute(char* cmd);
extern void queue_rx_string(char* string);
extern void command_unregister(const char* name);
#ifdef LL_KTRW_INTERNAL
extern void usbloader_init();
extern void pmgr_init();
extern void command_init();
extern void task_init();
extern void serial_init();
extern void interrupt_init();
extern void interrupt_teardown();
extern void task_irq_teardown();
extern uint32_t exception_vector[];
extern volatile void set_vbar_el3(uint64_t vec);
extern volatile void set_vbar_el1(uint64_t vec);
extern volatile void rebase_pc(uint64_t vec);
extern volatile void rebase_sp(uint64_t vec);
extern volatile uint64_t get_mmfr0(void);
extern volatile uint64_t get_migsts(void);
extern volatile uint64_t get_mpidr(void);
extern volatile void set_migsts(uint64_t val);
extern volatile void enable_mmu_el1(uint64_t ttbr, uint64_t tcr, uint64_t mair, uint64_t sctlr);
extern volatile void disable_mmu_el1();
extern volatile void enable_mmu_el3(uint64_t ttbr, uint64_t tcr, uint64_t mair);
extern volatile void disable_mmu_el3();
extern void lowlevel_cleanup(void);
extern void lowlevel_setup(uint64_t phys_off, uint64_t phys_size);
extern void map_full_ram(uint64_t phys_off, uint64_t phys_size);
#endif
