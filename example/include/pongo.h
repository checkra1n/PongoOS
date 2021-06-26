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
//  Copyright (C) 2019-2021 checkra1n team
//  This file is part of pongoOS.
//
#ifndef PONGOH
#define PONGOH

#include <mach-o/loader.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define DT_KEY_LEN 0x20
#define BOOT_LINE_LENGTH_iOS12 0x100
#define BOOT_LINE_LENGTH_iOS13 0x260

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
	uint32_t		__pad0;
	uint64_t		virtBase;			/* Virtual base of memory */
	uint64_t		physBase;			/* Physical base of memory */
	uint64_t		memSize;			/* Size of memory */
	uint64_t		topOfKernelData;	/* Highest physical address used in kernel data area */
	struct Boot_Video Video;				/* Video Information */
	uint32_t		machineType;		/* Machine Type */
	uint32_t		__pad1;
	void			*deviceTreeP;		/* Base of flattened device tree */
	uint32_t		deviceTreeLength;	/* Length of flattened tree */
	union {
		struct {
			char			CommandLine[BOOT_LINE_LENGTH_iOS12];	/* Passed in command line */
			uint32_t		__pad;
			uint64_t		bootFlags;		/* Additional flags specified by the bootloader */
			uint64_t		memSizeActual;		/* Actual size of memory */
		} iOS12;
		struct {
			char			CommandLine[BOOT_LINE_LENGTH_iOS13];	/* Passed in command line */
			uint32_t		__pad;
			uint64_t		bootFlags;		/* Additional flags specified by the bootloader */
			uint64_t		memSizeActual;		/* Actual size of memory */
		} iOS13;
	};
} __attribute__((packed)) boot_args;

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

struct memmap {
    uint64_t addr;
    uint64_t size;
};

/* Device Tree manipulation */

extern int dt_check(void* mem, uint32_t size, uint32_t* offp);
extern int dt_parse(dt_node_t* node, int depth, uint32_t* offp, int (*cb_node)(void*, dt_node_t*), void* cbn_arg, int (*cb_prop)(void*, dt_node_t*, int, const char*, void*, uint32_t), void* cbp_arg);
extern dt_node_t* dt_find(dt_node_t* node, const char* name);
extern void* dt_prop(dt_node_t* node, const char* key, uint32_t* lenp);
extern struct memmap* dt_alloc_memmap(dt_node_t* node, const char* name);
extern uint32_t dt_get_u32_prop(const char* device, const char* prop);
extern uint64_t dt_get_u64_prop(const char* device, const char* prop);
extern uint64_t dt_get_u64_prop_i(const char* device, const char* prop, uint32_t idx);

/* Task management */

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
    uint64_t t_flags;
    char name[32];
    uint32_t flags;
    struct task* next;
    struct task* prev;
    void (*crash_callback)();
};

extern void task_switch_irq(struct task* to_task);
extern void task_exit_irq();
extern void task_switch(struct task* to_task);
extern void task_link(struct task* to_task);
extern void task_unlink(struct task* to_task);
extern void task_irq_dispatch(uint32_t intr);
extern void task_yield_asserted();
extern void task_register_unlinked(struct task* task, void (*entry)());
extern void register_irq_handler(uint16_t irq_v, struct task* irq_handler);

/* Core functions */

struct pongo_exports {
    const char* name;
    void * value;
};

extern _Noreturn __attribute__((format(printf, 1, 2))) void panic(const char* string, ...);
extern void spin(uint32_t usec);
extern uint64_t get_ticks();
extern void usleep(uint32_t usec);
extern void sleep(uint32_t sec);
extern volatile uint8_t get_el(void);
extern void cache_invalidate(void *address, size_t size);
extern void cache_clean_and_invalidate(void *address, size_t size);
extern void clock_gate(uint64_t addr, char val);
extern void disable_preemption();
extern void enable_preemption();
extern void enable_interrupts();
extern void disable_interrupts();


/* Shell */

extern void command_putc(char val);
extern void command_puts(const char* val);
extern void command_register(const char* name, const char* desc, void (*cb)(const char* cmd, char* args));
extern char* command_tokenize(char* str, uint32_t strbufsz);
extern void queue_rx_string(char* string);

/* WDT */

extern void wdt_reset();
extern void wdt_enable();
extern void wdt_disable();

/* Global variables */

extern void (*preboot_hook)();
extern boot_args * gBootArgs;
extern void* gEntryPoint;
extern dt_node_t *gDeviceTree;
extern uint64_t gIOBase;
extern uint64_t gPMGRBase;
extern char* gDevType;
extern void* ramdisk_buf;
extern uint32_t ramdisk_size;
extern uint32_t autoboot_count;
extern uint8_t * loader_xfer_recv_data;
extern uint32_t loader_xfer_recv_count;
#endif
