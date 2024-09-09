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

// xcrun -sdk iphoneos clang -arch arm64 -o tfp0 tfp0.c -Wall -O3
// ldid -Stfp0.plist tfp0
#include <stdio.h>
#include <stdint.h>
#include <mach/mach.h>

extern kern_return_t mach_vm_allocate(vm_map_t target, mach_vm_address_t *address, mach_vm_size_t size, int flags);
extern kern_return_t mach_vm_deallocate(vm_map_t target, mach_vm_address_t address, mach_vm_size_t size);
extern kern_return_t mach_vm_read_overwrite(vm_map_read_t target, mach_vm_address_t address, mach_vm_size_t size, mach_vm_address_t data, mach_vm_size_t *outsize);
extern kern_return_t mach_vm_write(vm_map_t target, mach_vm_address_t address, vm_offset_t data, mach_msg_type_number_t size);

int main(void)
{
    int r = -1;
    kern_return_t ret = KERN_SUCCESS;
    task_t tfp0 = MACH_PORT_NULL;
    mach_vm_address_t page = 0;

    ret = task_for_pid(mach_task_self(), 0, &tfp0);
    printf("task_for_pid: %x, %s\n", tfp0, mach_error_string(ret));
    if(ret != KERN_SUCCESS || !MACH_PORT_VALID(tfp0))
    {
        goto out;
    }

    ret = mach_vm_allocate(tfp0, &page, 0x4000, VM_FLAGS_ANYWHERE);
    printf("mach_vm_allocate: 0x%" PRIx64 ", %s\n", page, mach_error_string(ret));
    if(ret != KERN_SUCCESS || page == 0)
    {
        goto out;
    }

    uint64_t data[] = { 0x4141414141414141, 0x74696873676e6167 };
    ret = mach_vm_write(tfp0, page, (vm_offset_t)data, sizeof(data));
    printf("mach_vm_write: %s\n", mach_error_string(ret));
    if(ret != KERN_SUCCESS)
    {
        goto out;
    }

    uint64_t check[2] = {};
    mach_vm_size_t size = sizeof(check);
    ret = mach_vm_read_overwrite(tfp0, page, sizeof(check), (mach_vm_address_t)check, &size);
    printf("mach_vm_read_overwrite: %s\n", mach_error_string(ret));
    if(ret != KERN_SUCCESS)
    {
        goto out;
    }

    printf("Data: 0x%016" PRIx64 " 0x%016" PRIx64 "\n", check[0], check[1]);
    if(check[0] != data[0] || check[1] != data[1])
    {
        goto out;
    }

    r = 0;

out:;
    if(page != 0)
    {
        mach_vm_deallocate(tfp0, page, 0x4000);
    }
    return r;
}
