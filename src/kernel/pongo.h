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
#ifndef PONGOH
#define PONGOH
#include <mach-o/loader.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <kerninfo.h>

#ifdef PONGO_PRIVATE
#include "framebuffer/fb.h"
#include "usb/usb.h"
#include "uart/uart.h"
#include "gpio/gpio.h"
#include "timer/timer.h"
#include "xnu/xnu.h"
#include "tz/tz.h"
#include "libDER/libDER_config.h"
#include "libDER/DER_Encode.h"
#include "libDER/DER_Decode.h"
#include "libDER/asn1Types.h"
#include "libDER/oids.h"
#include "mipi/mipi.h"
#include "aes/aes.h"
#include "sep/sep.h"
#endif

#define DT_KEY_LEN 0x20
#define BOOT_LINE_LENGTH_iOS12 0x100
#define BOOT_LINE_LENGTH_iOS13 0x260

extern int service_cmd(const char* name, int cmd_id, void* data_in, size_t in_size, void* data_out, size_t* out_size);

#define kSerialService "serial"
// these are for consumers
#define kSerialRXDequeue 1
#define kSerialTXQueue 2
// these are for providers
#define kSerialRXQueue 3
#define kSerialTXDequeue 4

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

extern volatile char gBootFlag;
#define BOOT_FLAG_DEFAULT 0
#define BOOT_FLAG_HARD 1
#define BOOT_FLAG_HOOK 2
#define BOOT_FLAG_LINUX 3
#define BOOT_FLAG_RAW 4

#define LINUX_DTREE_SIZE 262144
#define LINUX_CMDLINE_SIZE 4096

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
extern uint64_t gBootTimeTicks;

extern void (*sepfw_kpf_hook)(void* sepfw_bytes, size_t sepfw_size);

#define TASK_CAN_EXIT 1
#define TASK_LINKED 2
#define TASK_IRQ_HANDLER 4
#define TASK_PREEMPT 8
#define TASK_MASK_NEXT_IRQ 16
#define TASK_HAS_EXITED 32
#define TASK_WAS_LINKED 64
#define TASK_HAS_CRASHED 128
#define TASK_RESTART_ON_EXIT 256
#define TASK_SPAWN 512
#define TASK_FROM_PROC 1024
#define TASK_PLEASE_DEREF 2048

#define TASK_TYPE_MASK TASK_IRQ_HANDLER|TASK_PREEMPT|TASK_LINKED|TASK_CAN_EXIT|TASK_RESTART_ON_EXIT|TASK_SPAWN
#define TASK_REFCOUNT_GLOBAL 0x7fffffff
struct event {
	struct task* task_head;
};

extern struct vm_space kernel_vm_space;

#define VM_SPACE_SIZE 0x100000000
#define VM_SPACE_BASE 0xFFFFFFFE00000000
#define PAGING_INFO_ALLOC_ON_FAULT_MAGIC 0x00000000efef0008ULL
#define PAGING_INFO_ALLOC_ON_FAULT_MASK  0x00000000ffffffffULL
#define PAGING_INFO_ALLOC_ON_FAULT_INFO_MASK  0x000000ff00000000ULL
#define PAGING_INFO_ALLOC_ON_FAULT_INFO_GET(x) ((x & PAGING_INFO_ALLOC_ON_FAULT_INFO_MASK) >> 32ULL)
#define PAGING_INFO_ALLOC_ON_FAULT_INFO_SET(to, x) to = ((to & ~PAGING_INFO_ALLOC_ON_FAULT_INFO_MASK) | ((((uint64_t)x) << 32ULL) & PAGING_INFO_ALLOC_ON_FAULT_INFO_MASK));

#undef KERN_SUCCESS
#undef KERN_FAILURE
#undef KERN_VM_OOM
#undef VM_FLAGS_ANYWHERE
#undef VM_FLAGS_FIXED
#undef PROT_READ
#undef PROT_WRITE
#undef PROT_EXEC
#undef PROT_KERN_ONLY
#undef PROT_DEVICE
#undef PROT_PAGING_INFO

typedef enum {
    KERN_SUCCESS,
    KERN_FAILURE,
    KERN_VM_OOM
} err_t;
typedef enum {
    VM_FLAGS_ANYWHERE = 0,
    VM_FLAGS_FIXED = 1,
    VM_FLAGS_NOMAP = 2 // only reserves the VM space without doing anything with the lower level MM. call vm_space_map_page_physical_prot to actually associate a physical page manually! without this, pages will be populated on PF
} vm_flags_t;
typedef enum {
    PROT_READ = 1,
    PROT_WRITE = 2,
    PROT_EXEC = 4,
    PROT_KERN_ONLY = 8,
    PROT_DEVICE = 16,
    PROT_PAGING_INFO = 32
} vm_protect_t;

#ifdef PONGO_PRIVATE
#import "vfs.h"
#import "task.h"
#else
struct proc;
struct task;
struct vm_space;
#endif
#define PAGE_SIZE 0x4000
#define PAGE_MASK 0x3FFF
extern struct vm_space* vm_reference(struct vm_space* vmspace);
extern void vm_release(struct vm_space* vmspace);
extern struct vm_space* vm_create(struct vm_space* parent);
extern struct proc* proc_create(struct proc* parent, const char* proc_name, uint32_t flags);
extern void proc_reference(struct proc*);
extern void proc_release(struct proc*);
extern struct task* proc_create_task(struct proc* proc, void* entrypoint);
#define PROC_NO_VM 1
extern uint32_t loader_xfer_recv_size;
extern void resize_loader_xfer_data(uint32_t newsz);
extern bool vm_fault(struct vm_space* vmspace, uint64_t vma, vm_protect_t fault_prot);
extern err_t map_physical_range(struct vm_space* vmspace, uint64_t* va, uint64_t pa, uint32_t size, vm_flags_t flags, vm_protect_t prot);
extern struct vm_space* task_vm_space(struct task*);
extern void map_range_map(uint64_t* tt0, uint64_t va, uint64_t pa, uint64_t size, uint64_t sh, uint64_t attridx, bool overwrite, uint64_t paging_info, vm_protect_t prot, bool is_tt1);
extern err_t vm_space_map_page_physical_prot(struct vm_space* vmspace, uint64_t vaddr, uint64_t physical, vm_protect_t prot);
extern uint64_t ppage_alloc();
extern void ppage_free(uint64_t page);
extern void* page_alloc();
extern void page_free(void* page);
extern void* alloc_contig(uint32_t size);
extern void free_contig(void* base, uint32_t size);
extern void free_phys(uint64_t base, uint32_t size);
extern err_t vm_allocate(struct vm_space* vmspace, uint64_t* addr, uint64_t size, vm_flags_t flags);
extern err_t vm_deallocate(struct vm_space* vmspace, uint64_t addr, uint64_t size);
extern void vm_flush(struct vm_space* fl);
extern void vm_flush_by_addr(struct vm_space* fl, uint64_t va);
extern size_t memcpy_trap(void* dest, void* src, size_t size);
extern void task_critical_enter();
extern void task_critical_exit();
extern boot_args * gBootArgs;
extern void task_restart(struct task* task);
extern void* gEntryPoint;
extern dt_node_t *gDeviceTree;
extern uint64_t gIOBase;
extern uint64_t gPMGRBase;
extern char* gDevType;
extern void* ramdisk_buf;
extern uint32_t ramdisk_size;
extern char soc_name[9];
extern uint32_t socnum;
extern uint64_t vatophys_static(void* kva); // only safe to use with phystokva or alloc_contig's return value
extern uint32_t phys_get_entry(uint64_t pa);
extern void phys_set_entry(uint64_t pa, uint32_t val);
extern void mark_phys_wired(uint64_t pa, uint64_t size);
extern void phys_force_free(uint64_t pa, uint64_t size);
extern void phys_reference(uint64_t pa, uint64_t size);
extern void phys_dereference(uint64_t pa, uint64_t size);

typedef struct xnu_pf_range {
    uint64_t va;
    uint64_t size;
    uint8_t* cacheable_base;
    uint8_t* device_base;
} xnu_pf_range_t;

struct xnu_pf_patchset;

typedef struct xnu_pf_patch {
    bool (*pf_callback)(struct xnu_pf_patch* patch, void* cacheable_stream);
    bool is_required;
    bool has_fired;
    bool should_match;
    uint32_t pfjit_stolen_opcode;
    uint32_t pfjit_max_emit_size;
    uint32_t* (*pf_emit)(struct xnu_pf_patch* patch, struct xnu_pf_patchset *patchset,uint32_t* insn, uint32_t** insn_stream_end, uint8_t access_type);
    void (*pf_match)(struct xnu_pf_patch* patch, uint8_t access_type, void* preread, void* cacheable_stream);
    struct xnu_pf_patch* next_patch;
    uint32_t* pfjit_entry;
    uint32_t* pfjit_exit;
    uint8_t pf_data[0];
    char * name;

    //            patch->pf_match(XNU_PF_ACCESS_32BIT, reads, &stream[index], &dstream[index]);

} xnu_pf_patch_t;

typedef struct xnu_pf_patchset {
    xnu_pf_patch_t* patch_head;
    void* jit_matcher;
    uint64_t p0;
    uint8_t accesstype;
    bool is_required;
} xnu_pf_patchset_t;

#define XNU_PF_ACCESS_8BIT 0x8
#define XNU_PF_ACCESS_16BIT 0x10
#define XNU_PF_ACCESS_32BIT 0x20
#define XNU_PF_ACCESS_64BIT 0x40
#define TICKS_IN_1MS 24000
extern uint64_t xnu_slide_hdr_va(struct mach_header_64* header, uint64_t hdr_va);
extern uint64_t xnu_slide_value(struct mach_header_64* header);
extern struct mach_header_64* xnu_header();
extern xnu_pf_range_t* xnu_pf_range_from_va(uint64_t va, uint64_t size);
extern xnu_pf_range_t* xnu_pf_segment(struct mach_header_64* header, char* segment_name);
extern xnu_pf_range_t* xnu_pf_section(struct mach_header_64* header, void* segment, char* section_name);
extern xnu_pf_range_t* xnu_pf_all(struct mach_header_64* header);
extern xnu_pf_range_t* xnu_pf_all_x(struct mach_header_64* header);
extern void xnu_pf_disable_patch(xnu_pf_patch_t* patch);
extern void xnu_pf_enable_patch(xnu_pf_patch_t* patch);
extern struct segment_command_64* macho_get_segment(struct mach_header_64* header, const char* segname);
extern struct section_64 *macho_get_section(struct segment_command_64 *seg, const char *name);
extern struct mach_header_64* xnu_pf_get_first_kext(struct mach_header_64* kheader);
extern void hexdump(void *mem, unsigned int len);
extern xnu_pf_patch_t* xnu_pf_ptr_to_data(xnu_pf_patchset_t* patchset, uint64_t slide, xnu_pf_range_t* range, void* data, size_t datasz, bool required, bool (*callback)(struct xnu_pf_patch* patch, void* cacheable_stream));
extern xnu_pf_patch_t* xnu_pf_maskmatch(xnu_pf_patchset_t* patchset, char * name, uint64_t* matches, uint64_t* masks, uint32_t entryc, bool required, bool (*callback)(struct xnu_pf_patch* patch, void* cacheable_stream));
extern void xnu_pf_emit(xnu_pf_patchset_t* patchset); // converts a patchset to JIT
extern void xnu_pf_apply(xnu_pf_range_t* range, xnu_pf_patchset_t* patchset);
extern xnu_pf_patchset_t* xnu_pf_patchset_create(uint8_t pf_accesstype);
extern void xnu_pf_patchset_destroy(xnu_pf_patchset_t* patchset);
extern void* xnu_va_to_ptr(uint64_t va);
extern uint64_t xnu_ptr_to_va(void* ptr);
extern uint64_t xnu_rebase_va(uint64_t va);
extern uint64_t kext_rebase_va(uint64_t va);
extern struct mach_header_64* xnu_pf_get_kext_header(struct mach_header_64* kheader, const char* kext_bundle_id);
extern void xnu_pf_apply_each_kext(struct mach_header_64* kheader, xnu_pf_patchset_t* patchset);

#ifdef OVERRIDE_CACHEABLE_VIEW
#   define kCacheableView OVERRIDE_CACHEABLE_VIEW
#else
#   define kCacheableView 0x400000000ULL
#endif
struct pongo_exports {
    const char* name;
    void * value;
};
struct pongo_module_segment_info {
    char* name;
    uint64_t vm_addr;
    uint64_t vm_size;
    vm_protect_t prot;
};

struct pongo_module_info {
    const char* name;
    struct pongo_exports* exports;
    uint64_t vm_base;
    uint64_t vm_end;
    struct pongo_module_info* next;
    uint32_t segcount;
    struct pongo_module_segment_info segments[];
};
extern struct pongo_module_info* pongo_module_create(uint32_t segmentCount);
#define EXPORT_SYMBOL(x) {.name = "_"#x, .value = x}
#define EXPORT_SYMBOL_P(x) {.name = "_"#x, .value = (void*)&x}
extern void map_range(uint64_t va, uint64_t pa, uint64_t size, uint64_t sh, uint64_t attridx, bool overwrite);
void pongo_entry(uint64_t* kernel_args, void* entryp, void (*exit_to_el1_image)(void* boot_args, void* boot_entry_point));
int pongo_fiq_handler();
extern void (*preboot_hook)();
extern void (*sep_boot_hook)();
extern void (*rdload_hook)();
extern void vm_flush_by_addr_all_asid(uint64_t va);
extern void task_register_coop(struct task* task, void (*entry)()); // registers a cooperative task
extern void task_register_preempt_irq(struct task* task, void (*entry)(), int irq_id); // registers an irq handler
extern void task_register_irq(struct task* task, void (*entry)(), int irq_id); // registers an irq handler
extern void task_register(struct task* task, void (*entry)()); // register a preempt task
extern void task_yield();
extern void task_wait();
extern void task_exit();
extern void task_crash(const char* reason, ...);
extern void task_restart_and_link(struct task* task);
extern void task_exit_asserted();
extern void task_crash_asserted(const char* reason, ...);
extern struct task* task_create(const char* name, void (*entry)());
extern struct task* task_create_extended(const char* name, void (*entry)(), int task_type, uint64_t arg);
extern void task_reference(struct task* task);
extern void task_release(struct task* task);
extern void event_wait_asserted(struct event* ev);
extern void event_wait(struct event* ev);
extern void event_fire(struct event* ev);
extern void* alloc_static(uint32_t size); // memory returned by this will be added to the xnu static region, thus will persist after xnu boot
extern void task_bind_to_irq(struct task* task, int irq);
extern struct event command_handler_iter;

#ifdef memset
#   undef memset
#endif
extern void* memset(void *b, int c, size_t len);
extern void* memmem(const void* big, unsigned long blength, const void* little, unsigned long llength);
extern void* memstr(const void* big, unsigned long blength, const char* little);
extern void* memstr_partial(const void* big, unsigned long blength, const char* little);

extern uint64_t scheduler_ticks;
extern void invalidate_icache(void);
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
extern _Noreturn __attribute__((format(printf, 1, 2))) void panic(const char* string, ...);
extern void pmgr_reset();
extern void spin(uint32_t usec);
extern void task_set_sched_head(struct task* task);
extern void enable_interrupts();
extern void disable_interrupts();
extern uint64_t get_ticks();
extern void usleep(uint64_t usec);
extern void sleep(uint32_t sec);
extern uint32_t dt_get_u32_prop(const char* device, const char* prop);
extern uint64_t dt_get_u64_prop(const char* device, const char* prop);
extern uint64_t dt_get_u64_prop_i(const char* device, const char* prop, uint32_t idx);
extern void unmask_interrupt(uint32_t reg);
extern void mask_interrupt(uint32_t reg);
extern _Noreturn void wdt_reset();
extern void wdt_enable();
extern void wdt_disable();
extern bool linux_can_boot();
extern void linux_prep_boot();
extern void linux_boot();
extern void command_register(const char* name, const char* desc, void (*cb)(const char* cmd, char* args));
extern char* command_tokenize(char* str, uint32_t strbufsz);
extern uint8_t get_el(void);
extern uint64_t vatophys(uint64_t kvaddr);
extern void* phystokv(uint64_t paddr);
extern void cache_invalidate(void *address, size_t size);
extern void cache_clean_and_invalidate(void *address, size_t size);
extern void cache_clean(void *address, size_t size);
extern void register_irq_handler(uint16_t irq_v, struct task* irq_handler);
extern uint64_t device_clock_by_id(uint32_t id);
extern uint64_t device_clock_by_name(const char *name);
extern void clock_gate(uint64_t addr, char val);
extern void disable_preemption();
extern void enable_preemption();
extern void* alloc_contig(uint32_t size);
extern uint64_t alloc_phys(uint32_t size);
extern void task_suspend_self_asserted();
extern void command_execute(char* cmd);
extern void queue_rx_string(char* string);
extern void command_unregister(const char* name);
extern int hexparse(uint8_t *buf, char *s, size_t len);
extern void hexprint(uint8_t *data, size_t sz);

// Legacy
extern void print_register(uint64_t value);
extern void command_putc(char val);
extern void command_puts(const char* val);

extern void pongo_syscall_entry(struct task* task, uint32_t sysnr, uint64_t* state);
extern uint64_t vatophys_force(uint64_t kvaddr);
#ifdef PONGO_PRIVATE
#define STDOUT_BUFLEN 0x1000
extern volatile uint8_t command_in_progress;
extern void set_stdout_blocking(bool block);
extern void fetch_stdoutbuf(char* to, int* len);
extern void usbloader_init();
extern void pmgr_init();
extern void command_init();
extern void task_init();
extern void serial_init();
extern void interrupt_init();
extern void interrupt_teardown();
extern void task_irq_teardown();
extern uint32_t exception_vector[];
extern void set_vbar_el1(uint64_t vec);
extern void rebase_pc(uint64_t vec);
extern void rebase_sp(uint64_t vec);
extern uint64_t get_mmfr0(void);
extern uint64_t get_migsts(void);
extern uint64_t get_mpidr(void);
extern void set_migsts(uint64_t val);
extern void enable_mmu_el1(uint64_t ttbr0, uint64_t tcr, uint64_t mair, uint64_t ttbr1);
extern void disable_mmu_el1();
extern void lowlevel_cleanup(void);
extern void lowlevel_setup(uint64_t phys_off, uint64_t phys_size);
extern void map_full_ram(uint64_t phys_off, uint64_t phys_size);
extern uint64_t linear_kvm_alloc(uint32_t size);
static inline _Bool is_16k(void)
{
    return ((get_mmfr0() >> 20) & 0xf) == 0x1;
}
static inline void flush_tlb(void)
{
    __asm__ volatile("isb");
    __asm__ volatile("tlbi vmalle1\n");
    __asm__ volatile("dsb sy");
}
extern void task_real_unlink(struct task* task);
#include "hal/hal.h"

#endif

#endif
