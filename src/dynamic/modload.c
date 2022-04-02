/*
 * pongoOS - https://checkra.in
 *
 * Copyright (C) 2019-2022 checkra1n team
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
#include <wchar.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <mach-o/reloc.h>
#include <lzma/lzmadec.h>
#include <pongo.h>
#include <aes/aes.h>

/*void f_stack_chk_fail() { panic("stack overflow!"); }
uint64_t f_stack_chk_guard = 0x4141414141414141;
void *__memset_chk (void *dest, int c, size_t n, size_t dest_len) {
     if (n > dest_len) {
         panic("__memset_chk: overflow detected");
     }
     return memset(dest,c,n);
}
void *__memcpy_chk (void *dest, const void * src, size_t n, size_t dest_len) {
     if (n > dest_len) {
         panic("__memcpy_chk: overflow detected");
     }
     return memcpy(dest,src,n);
}*/

__asm__
(
    ".section __DATA, __pongo_exports\n"
    ".no_dead_strip pongo$exports\n"
    "pongo$exports:\n"
);
#define STR_(x) #x
#define STR(x) STR_(x)
#define PONGO_EXPORT_RAW(name, value)       \
__asm__                                     \
(                                           \
    ".section __TEXT, __cstring\n"          \
    "1:\n"                                  \
    "    .asciz \"_" #name "\"\n"           \
    ".section __DATA, __pongo_exports\n"    \
    ".align 4\n"                            \
    "    .8byte 1b\n"                       \
    "    .8byte " #value "\n"               \
)
#define PONGO_EXPORT_RENAME(name, orig) PONGO_EXPORT_RAW(name, _ ## orig)
#define PONGO_EXPORT(name) PONGO_EXPORT_RENAME(name, name)

// newlib support (syscall ABI)
PONGO_EXPORT(_exit);
PONGO_EXPORT(_read);
PONGO_EXPORT(_write);
PONGO_EXPORT(_close);
PONGO_EXPORT(_lseek);
PONGO_EXPORT(_open);
PONGO_EXPORT(_isatty);
PONGO_EXPORT(_fstat);
PONGO_EXPORT(__malloc_lock);
PONGO_EXPORT(__malloc_unlock);
PONGO_EXPORT(_getpid);
PONGO_EXPORT(_kill);
PONGO_EXPORT(_sbrk);

// newlib
// exporting global errno (no reentrant I/O functions provided currently)
#undef errno
PONGO_EXPORT(errno);

// Pongo
// TODO: sort & clean up, match headers
PONGO_EXPORT(xnu_pf_apply_each_kext);
PONGO_EXPORT(xnu_pf_get_first_kext);
PONGO_EXPORT(xnu_pf_get_kext_header);
PONGO_EXPORT(xnu_pf_disable_patch);
PONGO_EXPORT(xnu_pf_enable_patch);
PONGO_EXPORT(xnu_pf_ptr_to_data);
PONGO_EXPORT(xnu_pf_patchset_destroy);
PONGO_EXPORT(xnu_pf_patchset_create);
PONGO_EXPORT(print_register);
PONGO_EXPORT(alloc_static);
PONGO_EXPORT(xnu_slide_hdr_va);
PONGO_EXPORT(xnu_slide_value);
PONGO_EXPORT(xnu_header);
PONGO_EXPORT(xnu_platform);
PONGO_EXPORT(xnu_va_to_ptr);
PONGO_EXPORT(xnu_ptr_to_va);
PONGO_EXPORT(xnu_rebase_va);
PONGO_EXPORT(kext_rebase_va);
PONGO_EXPORT(xnu_pf_range_from_va);
PONGO_EXPORT(xnu_pf_segment);
PONGO_EXPORT(xnu_pf_section);
PONGO_EXPORT(xnu_pf_all);
PONGO_EXPORT(xnu_pf_all_x);
PONGO_EXPORT(xnu_pf_maskmatch);
PONGO_EXPORT(xnu_pf_emit);
PONGO_EXPORT(xnu_pf_apply);
PONGO_EXPORT(macho_get_segment);
PONGO_EXPORT(macho_get_section);
PONGO_EXPORT(dt_check);
PONGO_EXPORT(dt_parse);
PONGO_EXPORT(dt_find);
PONGO_EXPORT(dt_prop);
PONGO_EXPORT(event_fire);
PONGO_EXPORT(event_wait);
PONGO_EXPORT(event_wait_asserted);
PONGO_EXPORT(dt_alloc_memmap);
//PONGO_EXPORT(bzero);
//PONGO_EXPORT(memset);
PONGO_EXPORT(memcpy_trap);
PONGO_EXPORT(free_contig);
PONGO_EXPORT(phys_reference);
PONGO_EXPORT(phys_dereference);
PONGO_EXPORT(phys_force_free);
PONGO_EXPORT(mark_phys_wired);
PONGO_EXPORT(phys_get_entry);
PONGO_EXPORT(phys_set_entry);
PONGO_EXPORT(vm_flush);
PONGO_EXPORT(vm_flush_by_addr);
PONGO_EXPORT(free_phys);
PONGO_EXPORT(vm_space_map_page_physical_prot);
PONGO_EXPORT(proc_reference);
PONGO_EXPORT(proc_release);
PONGO_EXPORT(proc_create_task);
PONGO_EXPORT(vm_deallocate);
PONGO_EXPORT(vm_allocate);
//PONGO_EXPORT(strcmp);
PONGO_EXPORT(queue_rx_string);
//PONGO_EXPORT(strlen);
//PONGO_EXPORT(strcpy);
PONGO_EXPORT(task_create);
PONGO_EXPORT(task_create_extended);
PONGO_EXPORT(task_restart_and_link);
PONGO_EXPORT(task_critical_enter);
PONGO_EXPORT(task_critical_exit);
PONGO_EXPORT(task_bind_to_irq);
PONGO_EXPORT(task_release);
PONGO_EXPORT(task_reference);
PONGO_EXPORT(tz0_calculate_encrypted_block_addr);
PONGO_EXPORT(tz_blackbird);
PONGO_EXPORT(tz_lockdown);
PONGO_EXPORT(vatophys);
PONGO_EXPORT(vatophys_static);
PONGO_EXPORT(lock_take);
PONGO_EXPORT(lock_take_spin);
PONGO_EXPORT(lock_release);
//PONGO_EXPORT(memmove);
//PONGO_EXPORT(memmem);
PONGO_EXPORT(memstr);
PONGO_EXPORT(memstr_partial);
//PONGO_EXPORT(memcpy);
//PONGO_EXPORT(putc);
//PONGO_EXPORT(putchar);
//PONGO_EXPORT(puts);
//PONGO_EXPORT(strtoul);
PONGO_EXPORT(invalidate_icache);
PONGO_EXPORT(task_current);
PONGO_EXPORT(task_register_irq);
PONGO_EXPORT(task_register);
PONGO_EXPORT(task_yield);
PONGO_EXPORT(task_wait);
PONGO_EXPORT(task_exit);
PONGO_EXPORT(task_switch_irq);
PONGO_EXPORT(task_exit_irq);
PONGO_EXPORT(task_switch);
PONGO_EXPORT(task_link);
PONGO_EXPORT(task_unlink);
PONGO_EXPORT(task_irq_dispatch);
PONGO_EXPORT(task_yield_asserted);
PONGO_EXPORT(task_register_unlinked);
PONGO_EXPORT(panic);
PONGO_EXPORT(spin);
PONGO_EXPORT(get_ticks);
PONGO_EXPORT(usleep);
PONGO_EXPORT(sleep);
PONGO_EXPORT(dt_get_prop);
PONGO_EXPORT(dt_get_u32_prop);
PONGO_EXPORT(dt_get_u64_prop);
PONGO_EXPORT(dt_get_u64_prop_i);
PONGO_EXPORT(wdt_reset);
PONGO_EXPORT(wdt_enable);
PONGO_EXPORT(wdt_disable);
PONGO_EXPORT(command_putc);
PONGO_EXPORT(command_puts);
PONGO_EXPORT(command_register);
PONGO_EXPORT(command_tokenize);
PONGO_EXPORT(hexparse);
PONGO_EXPORT(hexprint);
PONGO_EXPORT(get_el);
PONGO_EXPORT(cache_invalidate);
PONGO_EXPORT(cache_clean_and_invalidate);
PONGO_EXPORT(register_irq_handler);
PONGO_EXPORT(device_clock_by_id);
PONGO_EXPORT(device_clock_by_name);
PONGO_EXPORT(clock_gate);
PONGO_EXPORT(disable_interrupts);
PONGO_EXPORT(enable_interrupts);
PONGO_EXPORT(alloc_contig);
PONGO_EXPORT(alloc_phys);
PONGO_EXPORT(map_physical_range);
PONGO_EXPORT(task_vm_space);
PONGO_EXPORT(usbloader_init);
PONGO_EXPORT(task_irq_teardown);
//PONGO_EXPORT(realloc);
//PONGO_EXPORT(malloc);
PONGO_EXPORT(phystokv);
//PONGO_EXPORT(free);
PONGO_EXPORT(hexdump);
//PONGO_EXPORT(memcmp);
PONGO_EXPORT(map_range);
PONGO_EXPORT(linear_kvm_alloc);
PONGO_EXPORT(vm_flush_by_addr_all_asid);
PONGO_EXPORT(vatophys_force);
PONGO_EXPORT(serial_disable_rx);
PONGO_EXPORT(serial_enable_rx);
//PONGO_EXPORT(__memset_chk);
//PONGO_EXPORT(__memcpy_chk);
PONGO_EXPORT(resize_loader_xfer_data);
PONGO_EXPORT(gBootArgs);
PONGO_EXPORT(gEntryPoint);
PONGO_EXPORT(gDeviceTree);
PONGO_EXPORT(gIOBase);
PONGO_EXPORT(gPMGRBase);
PONGO_EXPORT(unlzma_decompress);
PONGO_EXPORT(gDevType);
PONGO_EXPORT(soc_name);
PONGO_EXPORT(socnum);
PONGO_EXPORT(loader_xfer_recv_data);
PONGO_EXPORT(loader_xfer_recv_count);
PONGO_EXPORT(preboot_hook);
PONGO_EXPORT(ramdisk_buf);
PONGO_EXPORT(ramdisk_size);
PONGO_EXPORT(autoboot_count);
PONGO_EXPORT(sep_boot_hook);
PONGO_EXPORT(aes);
PONGO_EXPORT(_impure_ptr);
PONGO_EXPORT(loader_xfer_recv_size);
PONGO_EXPORT(overflow_mode);
PONGO_EXPORT(gFramebuffer);
PONGO_EXPORT(gWidth);
PONGO_EXPORT(gHeight);
PONGO_EXPORT(gRowPixels);
PONGO_EXPORT(y_cursor);
PONGO_EXPORT(x_cursor);
PONGO_EXPORT(scale_factor);
//PONGO_EXPORT_RENAME(__stack_chk_guard, f_stack_chk_guard);
//PONGO_EXPORT_RENAME(__stack_chk_fail, f_stack_chk_fail);
//PONGO_EXPORT_RENAME(iprintf, iprintf);
PONGO_EXPORT_RENAME(printf, iprintf);
//PONGO_EXPORT_RENAME(fiprintf, fiprintf);
PONGO_EXPORT_RENAME(fprintf, fiprintf);
//PONGO_EXPORT_RENAME(viprintf, viprintf);
PONGO_EXPORT_RENAME(vprintf, viprintf);
//PONGO_EXPORT_RENAME(vfiprintf, vfiprintf);
PONGO_EXPORT_RENAME(vfprintf, vfiprintf);
//PONGO_EXPORT_RENAME(sniprintf, sniprintf);
PONGO_EXPORT_RENAME(snprintf, sniprintf);
//PONGO_EXPORT_RENAME(vsniprintf, vsniprintf);
PONGO_EXPORT_RENAME(vsnprintf, vsniprintf);
__asm__
(
    ".section __DATA, __pongo_exports\n"
    ".align 4\n"
    "    .8byte 0x0\n"
    "    .8byte 0x0\n"
);

extern struct pongo_exports public_api[] __asm__("section$start$__DATA$__pongo_exports");

void link_exports(struct pongo_exports* export) {
    struct pongo_exports* api = &public_api[0];
    while (1) {
        while (api->name) {
            api++;
        }
        if (!api->name && api->value) {
            api = (struct pongo_exports*)api->value;
            continue;
        } else if (!api->name && !api->value) {
            api->value = (void*)export;
            return;
        }
    }
}
void* resolve_symbol(const char* name) {
    struct pongo_exports* api = &public_api[0];
    while (1) {
        while (api->name) {
            if (strcmp(api->name, name) == 0) {
                return api->value;
            }
            api++;
        }
        if (!api->name && api->value) {
            // we have another set of exported symbols we can walk
            api = (struct pongo_exports*)api->value;
            continue;
        }
        break;
    }
    iprintf("resolve_symbol: missing symbol: %s\n", name);
    iprintf("usbloader-linker could not load this module!!\n");
    return 0;
}
static struct pongo_module_info* head;
struct pongo_module_info* pongo_module_create(uint32_t segmentCount) {
    struct pongo_module_info* mod = calloc(sizeof (struct pongo_module_info) + sizeof(struct pongo_module_segment_info) * segmentCount, 1);
    disable_interrupts();
    mod->next = head;
    mod->segcount = segmentCount;
    head = mod;
    enable_interrupts();
    return mod;
}
void pongo_module_print_list() {
    struct pongo_module_info* cur = head;
    while (cur) {
        iprintf(" | %26s @ 0x%llx->0x%llx\n", cur->name, cur->vm_base, cur->vm_end);
        for (uint32_t i = 0; i < cur->segcount; i++) {
            iprintf(" |---> %22s @ 0x%08llx, size 0x%06llx (%s%s%s)\n", cur->segments[i].name, cur->vm_base + cur->segments[i].vm_addr, cur->segments[i].vm_size, cur->segments[i].prot & PROT_READ ? "r" : "-", cur->segments[i].prot & PROT_WRITE ? "w" : "-", cur->segments[i].prot & PROT_EXEC ? "x" : "-");
        }
        cur = cur->next;
    }
}
