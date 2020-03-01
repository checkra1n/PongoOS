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
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <mach-o/reloc.h>
#include <lzma/lzmadec.h>

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
void printf32(const char* str, uint32_t val) {
     iprintf(str,val);
}
struct pongo_exports public_api[] = {
    EXPORT_SYMBOL(dt_check),
    EXPORT_SYMBOL(dt_parse),
    EXPORT_SYMBOL(dt_find),
    EXPORT_SYMBOL(dt_prop),
    EXPORT_SYMBOL(dt_alloc_memmap),
    EXPORT_SYMBOL(memset),
    EXPORT_SYMBOL(strcmp),
    EXPORT_SYMBOL(queue_rx_string),
    EXPORT_SYMBOL(strlen),
    EXPORT_SYMBOL(strcpy),
    EXPORT_SYMBOL(memmem),
    EXPORT_SYMBOL(memstr),
    EXPORT_SYMBOL(memstr_partial),
    EXPORT_SYMBOL(memcpy),
    EXPORT_SYMBOL(putc),
    EXPORT_SYMBOL(putchar),
    EXPORT_SYMBOL(puts),
    EXPORT_SYMBOL(printf32),
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
    EXPORT_SYMBOL(get_el),
    EXPORT_SYMBOL(cache_invalidate),
    EXPORT_SYMBOL(cache_clean_and_invalidate),
    EXPORT_SYMBOL(register_irq_handler),
    EXPORT_SYMBOL(clock_gate),
    EXPORT_SYMBOL(disable_preemption),
    EXPORT_SYMBOL(enable_preemption),
    EXPORT_SYMBOL(disable_interrupts),
    EXPORT_SYMBOL(enable_interrupts),
    EXPORT_SYMBOL(alloc_contig),
    EXPORT_SYMBOL(usbloader_init),
    EXPORT_SYMBOL(pmgr_init),
    EXPORT_SYMBOL(command_init),
    EXPORT_SYMBOL(serial_init),
    EXPORT_SYMBOL(task_irq_teardown),
    EXPORT_SYMBOL(realloc),
    EXPORT_SYMBOL(malloc),
    EXPORT_SYMBOL(free),
    EXPORT_SYMBOL(screen_init),
    EXPORT_SYMBOL(screen_puts),
    EXPORT_SYMBOL(screen_write),
    EXPORT_SYMBOL(screen_putc),
    EXPORT_SYMBOL(screen_mark_banner),
    EXPORT_SYMBOL(serial_putc),
    EXPORT_SYMBOL(serial_disable_rx),
    EXPORT_SYMBOL(serial_enable_rx),
    EXPORT_SYMBOL(__memset_chk),
    EXPORT_SYMBOL(__memcpy_chk),
    EXPORT_SYMBOL_P(gBootArgs),
    EXPORT_SYMBOL_P(gEntryPoint),
    EXPORT_SYMBOL_P(gDeviceTree),
    EXPORT_SYMBOL_P(gIOBase),
    EXPORT_SYMBOL_P(gPMGRBase),
    EXPORT_SYMBOL(unlzma_decompress),
    EXPORT_SYMBOL_P(gDevType),
    EXPORT_SYMBOL_P(loader_xfer_recv_data),
    EXPORT_SYMBOL_P(loader_xfer_recv_count),
    EXPORT_SYMBOL_P(preboot_hook),
    EXPORT_SYMBOL_P(ramdisk_buf),
    EXPORT_SYMBOL_P(ramdisk_size),
    EXPORT_SYMBOL_P(autoboot_count),
    {.name = "__stack_chk_guard", .value = &f_stack_chk_guard},
    {.name = "__stack_chk_fail", .value = &f_stack_chk_fail},
    {.name = "printf_", .value = iprintf},
    {.name = "printf", .value = iprintf},
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
    iprintf("usbloader-linker could not load this module!!");
    return 0;
}
