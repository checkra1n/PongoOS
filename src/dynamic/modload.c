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
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <mach-o/reloc.h>
#include <lzma/lzmadec.h>
#include <pongo.h>
#include <aes/aes.h>

void f_stack_chk_fail() { panic("stack overflow!"); }
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
}

struct pongo_exports public_api[] = {
    EXPORT_SYMBOL(xnu_pf_apply_each_kext),
    EXPORT_SYMBOL(xnu_pf_get_first_kext),
    EXPORT_SYMBOL(xnu_pf_get_kext_header),
    EXPORT_SYMBOL(xnu_pf_disable_patch),
    EXPORT_SYMBOL(xnu_pf_enable_patch),
    EXPORT_SYMBOL(xnu_pf_ptr_to_data),
    EXPORT_SYMBOL(xnu_pf_patchset_destroy),
    EXPORT_SYMBOL(xnu_pf_patchset_create),
    EXPORT_SYMBOL(print_register),
    EXPORT_SYMBOL(alloc_static),
    EXPORT_SYMBOL(xnu_slide_hdr_va),
    EXPORT_SYMBOL(xnu_slide_value),
    EXPORT_SYMBOL(xnu_header),
    EXPORT_SYMBOL(xnu_va_to_ptr),
    EXPORT_SYMBOL(xnu_ptr_to_va),
    EXPORT_SYMBOL(xnu_rebase_va),
    EXPORT_SYMBOL(kext_rebase_va),
    EXPORT_SYMBOL(xnu_pf_range_from_va),
    EXPORT_SYMBOL(xnu_pf_segment),
    EXPORT_SYMBOL(xnu_pf_section),
    EXPORT_SYMBOL(xnu_pf_all),
    EXPORT_SYMBOL(xnu_pf_all_x),
    EXPORT_SYMBOL(xnu_pf_maskmatch),
    EXPORT_SYMBOL(xnu_pf_emit),
    EXPORT_SYMBOL(xnu_pf_apply),
    EXPORT_SYMBOL(macho_get_segment),
    EXPORT_SYMBOL(macho_get_section),
    EXPORT_SYMBOL(dt_check),
    EXPORT_SYMBOL(dt_parse),
    EXPORT_SYMBOL(dt_find),
    EXPORT_SYMBOL(dt_prop),
    EXPORT_SYMBOL(event_fire),
    EXPORT_SYMBOL(event_wait),
    EXPORT_SYMBOL(event_wait_asserted),
    EXPORT_SYMBOL(dt_alloc_memmap),
    EXPORT_SYMBOL(bzero),
    EXPORT_SYMBOL(memset),
    EXPORT_SYMBOL(memcpy_trap),
    EXPORT_SYMBOL(free_contig),
    EXPORT_SYMBOL(phys_reference),
    EXPORT_SYMBOL(phys_dereference),
    EXPORT_SYMBOL(phys_force_free),
    EXPORT_SYMBOL(mark_phys_wired),
    EXPORT_SYMBOL(phys_get_entry),
    EXPORT_SYMBOL(phys_set_entry),
    EXPORT_SYMBOL(vm_flush),
    EXPORT_SYMBOL(vm_flush_by_addr),
    EXPORT_SYMBOL(free_phys),
    EXPORT_SYMBOL(vm_space_map_page_physical_prot),
    EXPORT_SYMBOL(proc_reference),
    EXPORT_SYMBOL(proc_release),
    EXPORT_SYMBOL(proc_create_task),
    EXPORT_SYMBOL(vm_deallocate),
    EXPORT_SYMBOL(vm_allocate),
    EXPORT_SYMBOL(strcmp),
    EXPORT_SYMBOL(queue_rx_string),
    EXPORT_SYMBOL(strlen),
    EXPORT_SYMBOL(strcpy),
    EXPORT_SYMBOL(task_create),
    EXPORT_SYMBOL(task_create_extended),
    EXPORT_SYMBOL(task_restart_and_link),
    EXPORT_SYMBOL(task_critical_enter),
    EXPORT_SYMBOL(task_critical_exit),
    EXPORT_SYMBOL(task_bind_to_irq),
    EXPORT_SYMBOL(task_release),
    EXPORT_SYMBOL(task_reference),
    EXPORT_SYMBOL(tz0_calculate_encrypted_block_addr),
    EXPORT_SYMBOL(tz_blackbird),
    EXPORT_SYMBOL(tz_lockdown),
    EXPORT_SYMBOL(vatophys),
    EXPORT_SYMBOL(vatophys_static),
    EXPORT_SYMBOL(lock_take),
    EXPORT_SYMBOL(lock_take_spin),
    EXPORT_SYMBOL(lock_release),
    EXPORT_SYMBOL(memmove),
    EXPORT_SYMBOL(memmem),
    EXPORT_SYMBOL(memstr),
    EXPORT_SYMBOL(memstr_partial),
    EXPORT_SYMBOL(memcpy),
    EXPORT_SYMBOL(putc),
    EXPORT_SYMBOL(putchar),
    EXPORT_SYMBOL(puts),
    EXPORT_SYMBOL(strtoul),
    EXPORT_SYMBOL(invalidate_icache),
    EXPORT_SYMBOL(task_current),
    EXPORT_SYMBOL(task_register_irq),
    EXPORT_SYMBOL(task_register),
    EXPORT_SYMBOL(task_yield),
    EXPORT_SYMBOL(task_wait),
    EXPORT_SYMBOL(task_exit),
    EXPORT_SYMBOL(task_switch_irq),
    EXPORT_SYMBOL(task_exit_irq),
    EXPORT_SYMBOL(task_switch),
    EXPORT_SYMBOL(task_link),
    EXPORT_SYMBOL(task_unlink),
    EXPORT_SYMBOL(task_irq_dispatch),
    EXPORT_SYMBOL(task_yield_asserted),
    EXPORT_SYMBOL(task_register_unlinked),
    EXPORT_SYMBOL(panic),
    EXPORT_SYMBOL(spin),
    EXPORT_SYMBOL(get_ticks),
    EXPORT_SYMBOL(usleep),
    EXPORT_SYMBOL(sleep),
    EXPORT_SYMBOL(dt_get_prop),
    EXPORT_SYMBOL(dt_get_u32_prop),
    EXPORT_SYMBOL(dt_get_u64_prop),
    EXPORT_SYMBOL(dt_get_u64_prop_i),
    EXPORT_SYMBOL(wdt_reset),
    EXPORT_SYMBOL(wdt_enable),
    EXPORT_SYMBOL(wdt_disable),
    EXPORT_SYMBOL(command_putc),
    EXPORT_SYMBOL(command_puts),
    EXPORT_SYMBOL(command_register),
    EXPORT_SYMBOL(command_tokenize),
    EXPORT_SYMBOL(hexparse),
    EXPORT_SYMBOL(hexprint),
    EXPORT_SYMBOL(get_el),
    EXPORT_SYMBOL(cache_invalidate),
    EXPORT_SYMBOL(cache_clean_and_invalidate),
    EXPORT_SYMBOL(register_irq_handler),
    EXPORT_SYMBOL(device_clock_by_id),
    EXPORT_SYMBOL(device_clock_by_name),
    EXPORT_SYMBOL(clock_gate),
    EXPORT_SYMBOL(disable_interrupts),
    EXPORT_SYMBOL(enable_interrupts),
    EXPORT_SYMBOL(alloc_contig),
    EXPORT_SYMBOL(alloc_phys),
    EXPORT_SYMBOL(map_physical_range),
    EXPORT_SYMBOL(task_vm_space),
    EXPORT_SYMBOL(usbloader_init),
    EXPORT_SYMBOL(task_irq_teardown),
    EXPORT_SYMBOL(realloc),
    EXPORT_SYMBOL(malloc),
    EXPORT_SYMBOL(phystokv),
    EXPORT_SYMBOL(free),
    EXPORT_SYMBOL(hexdump),
    EXPORT_SYMBOL(memcmp),
    EXPORT_SYMBOL(map_range),
    EXPORT_SYMBOL(linear_kvm_alloc),
    EXPORT_SYMBOL(vm_flush_by_addr_all_asid),
    EXPORT_SYMBOL(vatophys_force),
    EXPORT_SYMBOL(serial_disable_rx),
    EXPORT_SYMBOL(serial_enable_rx),
    EXPORT_SYMBOL(__memset_chk),
    EXPORT_SYMBOL(__memcpy_chk),
    EXPORT_SYMBOL(resize_loader_xfer_data),
    EXPORT_SYMBOL_P(gBootArgs),
    EXPORT_SYMBOL_P(gEntryPoint),
    EXPORT_SYMBOL_P(gDeviceTree),
    EXPORT_SYMBOL_P(gIOBase),
    EXPORT_SYMBOL_P(gPMGRBase),
    EXPORT_SYMBOL(unlzma_decompress),
    EXPORT_SYMBOL_P(gDevType),
    EXPORT_SYMBOL_P(soc_name),
    EXPORT_SYMBOL_P(socnum),
    EXPORT_SYMBOL_P(loader_xfer_recv_data),
    EXPORT_SYMBOL_P(loader_xfer_recv_count),
    EXPORT_SYMBOL_P(preboot_hook),
    EXPORT_SYMBOL_P(ramdisk_buf),
    EXPORT_SYMBOL_P(ramdisk_size),
    EXPORT_SYMBOL_P(autoboot_count),
    EXPORT_SYMBOL_P(sep_boot_hook),
    EXPORT_SYMBOL_P(aes),
    EXPORT_SYMBOL_P(_impure_ptr),
    EXPORT_SYMBOL_P(loader_xfer_recv_size),
    EXPORT_SYMBOL_P(overflow_mode),
    EXPORT_SYMBOL_P(gFramebuffer),
    EXPORT_SYMBOL_P(gWidth),
    EXPORT_SYMBOL_P(gHeight),
    EXPORT_SYMBOL_P(gRowPixels),
    EXPORT_SYMBOL_P(y_cursor),
    EXPORT_SYMBOL_P(x_cursor),
    EXPORT_SYMBOL_P(scale_factor),
    {.name = "___stack_chk_guard", .value = &f_stack_chk_guard},
    {.name = "___stack_chk_fail", .value = &f_stack_chk_fail},
    {.name = "_iprintf", .value = iprintf},
    {.name = "_printf", .value = iprintf},
    {.name = "_fiprintf", .value = fiprintf},
    {.name = "_fprintf", .value = fiprintf},
    {.name = "_viprintf", .value = viprintf},
    {.name = "_vprintf", .value = viprintf},
    {.name = "_vfiprintf", .value = vfiprintf},
    {.name = "_vfprintf", .value = vfiprintf},
    {.name = "_sniprintf", .value = sniprintf},
    {.name = "_snprintf", .value = sniprintf},
    {.name = "_vsniprintf", .value = vsniprintf},
    {.name = "_vsnprintf", .value = vsniprintf},
    {.name = NULL}
};
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
