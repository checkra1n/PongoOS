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

// xcrun -sdk iphoneos clang -arch arm64 -o vm_map_protect vm_map_protect.c -Wall -O3
#include <stdint.h>
#include <stdio.h>
#include <mach/mach.h>
#include <libkern/OSCacheControl.h>

extern kern_return_t mach_vm_allocate(vm_map_t target, mach_vm_address_t *address, mach_vm_size_t size, int flags);
extern kern_return_t mach_vm_protect(vm_map_t target, mach_vm_address_t address, mach_vm_size_t size, boolean_t max, vm_prot_t prot);
extern kern_return_t mach_vm_region_recurse(vm_map_read_t target, mach_vm_address_t *address, mach_vm_size_t *size, natural_t *nesting_depth, vm_region_recurse_info_t info, mach_msg_type_number_t *infoCnt);

int main(void)
{
    mach_vm_address_t addr = 0;
    kern_return_t ret = mach_vm_allocate(mach_task_self(), &addr, 0x4000, VM_FLAGS_ANYWHERE);
    printf("mach_vm_allocate: %s\n", mach_error_string(ret));
    if(ret != KERN_SUCCESS)
    {
        return -1;
    }

    ret = mach_vm_protect(mach_task_self(), addr, 0x4000, 0, VM_PROT_ALL);
    printf("mach_vm_protect: %s\n", mach_error_string(ret));
    if(ret != KERN_SUCCESS)
    {
        return -1;
    }

    mach_vm_address_t addr_check = addr;
    mach_vm_size_t size_check = 0x4000;
    natural_t depth = 256;
    vm_region_submap_short_info_data_64_t info = {};
    mach_msg_type_number_t cnt = VM_REGION_SUBMAP_SHORT_INFO_COUNT_64;
    ret = mach_vm_region_recurse(mach_task_self(), &addr_check, &size_check, &depth, (vm_region_recurse_info_t)&info, &cnt);
    printf("mach_vm_region_recurse: %s\n", mach_error_string(ret));
    if(ret != KERN_SUCCESS)
    {
        return -1;
    }

    if(addr_check != addr || size_check != 0x4000)
    {
        printf("Bad addr/size returned from mach_vm_region_recurse!\n");
        printf("Want 0x%" PRIx64 "/0x%" PRIx64 ", have 0x%" PRIx64 "/0x%" PRIx64 "\n", addr, 0x4000ULL, addr_check, size_check);
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
    if(info.protection != VM_PROT_ALL || info.max_protection != VM_PROT_ALL)
    {
        return -1;
    }

    uint32_t *op = (uint32_t*)addr;
    op[0] = 0x528266e0; // mov w0, 0x1337
    op[1] = 0xd65f03c0; // ret

    sys_dcache_flush(op, 8);
    sys_icache_invalidate(op, 8);

    uint32_t (*shc)(void) = (uint32_t(*)(void))addr;
    uint32_t result = shc();
    printf("Result: 0x%x\n", result);

    return 0;
}
