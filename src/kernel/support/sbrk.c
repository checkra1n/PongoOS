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
#include <pongo.h>

uint64_t heap_base = 0xe00000000;
uint64_t heap_cursor = 0xe00000000;
uint64_t heap_end = 0xe00000000;
extern struct vm_space kernel_vm_space;
caddr_t _sbrk(int size) {
    disable_interrupts();
    uint64_t cursor_copy = heap_cursor;
    heap_cursor += size;
    while (heap_cursor > heap_end) {
        vm_space_map_page_physical_prot(&kernel_vm_space, heap_end, ppage_alloc(), PROT_READ|PROT_WRITE|PROT_KERN_ONLY);
        heap_end += 0x4000;
    }
    enable_interrupts();
    return (caddr_t)cursor_copy;
}
