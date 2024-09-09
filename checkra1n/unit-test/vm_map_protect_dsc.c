/*
 * pongoOS - https://checkra.in
 *
 * Copyright (C) 2023 checkra1n team
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

// xcrun -sdk iphoneos clang -arch arm64 -o vm_map_protect_dsc vm_map_protect_dsc.c -Wall -O3
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <mach/mach.h>
#include <libkern/OSCacheControl.h>

extern kern_return_t mach_vm_protect(vm_map_t target, mach_vm_address_t address, mach_vm_size_t size, boolean_t max, vm_prot_t prot);
extern kern_return_t mach_vm_region_recurse(vm_map_read_t target, mach_vm_address_t *address, mach_vm_size_t *size, natural_t *nesting_depth, vm_region_recurse_info_t info, mach_msg_type_number_t *infoCnt);
extern uint32_t xpc_test_symbols_exported(void);

static int require_prot(mach_vm_address_t addr, mach_vm_size_t size, vm_prot_t prot, vm_prot_t prot_cur, vm_prot_t prot_max)
{
    kern_return_t ret = mach_vm_protect(mach_task_self(), addr, size, 0, prot);
    printf("mach_vm_protect: %s\n", mach_error_string(ret));
    if(ret != KERN_SUCCESS)
    {
        return -1;
    }

    mach_vm_address_t addr_check = addr;
    mach_vm_size_t size_check = size;
    natural_t depth = 256;
    vm_region_submap_short_info_data_64_t info = {};
    mach_msg_type_number_t cnt = VM_REGION_SUBMAP_SHORT_INFO_COUNT_64;
    ret = mach_vm_region_recurse(mach_task_self(), &addr_check, &size_check, &depth, (vm_region_recurse_info_t)&info, &cnt);
    printf("mach_vm_region_recurse: %s\n", mach_error_string(ret));
    if(ret != KERN_SUCCESS)
    {
        return -1;
    }

    if(addr_check != (addr & ~0x3fffULL) || size_check != ((size + 0x3fffULL) & ~0x3fffULL))
    {
        printf("Bad addr/size returned from mach_vm_region_recurse!\n");
        printf("Want 0x%" PRIx64 "/0x%" PRIx64 ", have 0x%" PRIx64 "/0x%" PRIx64 "\n", addr, size, addr_check, size_check);
        return -1;
    }

    printf("Prot: %c%c%c/%c%c%c\n"
          , info.protection     & VM_PROT_READ    ? 'r' : '-'
          , info.protection     & VM_PROT_WRITE   ? 'w' : '-'
          , info.protection     & VM_PROT_EXECUTE ? 'x' : '-'
          , info.max_protection & VM_PROT_READ    ? 'r' : '-'
          , info.max_protection & VM_PROT_WRITE   ? 'w' : '-'
          , info.max_protection & VM_PROT_EXECUTE ? 'x' : '-'
    );
    if(info.protection != prot_cur || info.max_protection != prot_max)
    {
        return -1;
    }

    return 0;
}

int main(void)
{
    void *libxpc = dlopen("/usr/lib/system/libxpc.dylib", RTLD_LAZY);
    printf("dlopen: 0x%" PRIx64 "\n", (uint64_t)libxpc);
    if(!libxpc)
    {
        return -1;
    }

    void *test_sym = dlsym(libxpc, "xpc_test_symbols_exported");
    printf("dlsym: 0x%" PRIx64 "\n", (uint64_t)test_sym);
    if(!test_sym)
    {
        return -1;
    }

    if(require_prot((mach_vm_address_t)test_sym, 0x4, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY, VM_PROT_READ | VM_PROT_WRITE, VM_PROT_ALL) != 0)
    {
        return -1;
    }

    *(uint32_t*)test_sym = 0x528266e0; // mov w0, 0x1337

    sys_dcache_flush(test_sym, 0x4);

    if(require_prot((mach_vm_address_t)test_sym, 0x4, VM_PROT_READ | VM_PROT_EXECUTE, VM_PROT_READ | VM_PROT_EXECUTE, VM_PROT_ALL) != 0)
    {
        return -1;
    }

    sys_icache_invalidate(test_sym, 0x4);

    uint32_t result = xpc_test_symbols_exported();
    printf("Result: 0x%x\n", result);

    return 0;
}
