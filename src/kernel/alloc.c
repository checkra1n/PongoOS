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
#include <pongo.h>

uint64_t alloc_static_base = 0;
uint64_t alloc_static_current = 0;
uint64_t alloc_static_end = 0;
uint64_t alloc_heap_base = 0;
uint64_t alloc_heap_current = 0;
uint64_t alloc_heap_end = 0;
uint64_t topkd = 0;

void alloc_init() {
    if (alloc_static_base) panic("alloc_init misuse");
    alloc_static_current = alloc_static_base = (kCacheableView - 0x800000000 + gBootArgs->topOfKernelData) & (~0x3fff);
    alloc_static_end = 0x417fe0000;

    extern uint64_t __bss_end[] __asm__("segment$end$__DATA");
    alloc_heap_base = (((uint64_t)__bss_end) + 0x7fff) & (~0x3fff);
    alloc_heap_base &= 0xFFFFFFFF;
    alloc_heap_base += kCacheableView;
    alloc_heap_end = (((uint64_t)((kCacheableView - 0x800000000 + gBootArgs->physBase) + gBootArgs->memSize)) + 0x3fff) & (~0x3fff) - 1024*1024;

    uint64_t alloc_static_hardcap = alloc_static_base + (1024 * 1024 * 64);
    if (alloc_static_end > alloc_static_hardcap) {
        if ((alloc_static_end - alloc_static_hardcap) > (alloc_heap_end - alloc_heap_base)) {
            alloc_heap_end = alloc_static_end;
            alloc_static_end = alloc_static_hardcap;
            alloc_heap_base = alloc_static_hardcap;
        }
    }

    alloc_heap_current = alloc_heap_base;
}
void* alloc_static(uint32_t size) { // memory returned by this will be added to the xnu static region, thus will persist after xnu boot
    if (!alloc_static_base) {
        alloc_init();
    }
    void* rv = (void*)alloc_static_current;
    alloc_static_current += (size + 0x3fff) & (~0x3fff);
    if (alloc_static_current > alloc_static_end) panic("ran out of static region");
    gBootArgs->topOfKernelData += (size + 0x3fff) & (~0x3fff);
    return rv;
}

void* alloc_contig(uint32_t size) {
    if (!alloc_static_base) {
        alloc_init();
    }
    void* rv = (void*)alloc_heap_current;
    alloc_heap_current += (size + 0x3fff) & (~0x3fff);
    if (alloc_heap_current > alloc_heap_end) panic("ran out of heap region");
    return rv;
}

