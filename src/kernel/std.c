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

OBFUSCATE_C_FUNC(void* memstr(const void* big, unsigned long blength, const char* little))
{
    return memmem(big, blength, (void*)little, strlen(little) + 1);
}
OBFUSCATE_C_FUNC(void* memstr_partial(const void* big, unsigned long blength, const char* little))
{
    return memmem(big, blength, (void*)little, strlen(little));
}

char panic_did_enter = 0;
void panic(const char* str) {
    disable_interrupts();
    
    if (panic_did_enter) {
        iprintf("\ndouble panic: %s\n", str);
        while(1) {}
    }    
    panic_did_enter = 1;
    
    iprintf("\npanic: %s\ncrashed task: ", str);
    if (task_current() && task_current()->name[0])
        puts(task_current()->name);
    else puts("unknown");

    puts("crashed in required task, resetting..");

    wdt_reset();
}
char* conv = "0123456789abcdef";
void print_register(uint64_t value)
{
    putc('0', stdout);
    putc('x', stdout);
    char convval[16];
    for (int i = 0; i < 16;) {
        convval[i++] = conv[(value & 0xF)];
        convval[i++] = conv[(value & 0xF0) >> 4];
        value >>= 8;
    }
    for (int i = 0; i < 16; i++) {
        putc(convval[15 - i], stdout);
    }
    puts("");
}
void _putchar(char character)  {
    if (character == '\n') serial_putc('\r');
    putc(character, stdout);
}
void print_hex_number(uint64_t value)
{
    disable_interrupts();
    putc('0', stdout);
    putc('x', stdout);
    char convval[16];
    for (int i = 0; i < 16;) {
        convval[i++] = conv[(value & 0xF)];
        convval[i++] = conv[(value & 0xF0) >> 4];
        value >>= 8;
    }
    char leading0 = 1;
    for (int i = 0; i < 16; i++) {
        if (convval[15 - i] != '0') leading0 = 0;
        if (!leading0 || i == 15)
            putc(convval[15 - i], stdout);
    }
    enable_interrupts();
}
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
    alloc_static_end = alloc_heap_current = alloc_heap_base = alloc_static_base + (1024 * 1024 * 128);
    alloc_heap_end = 0x427ff0000;
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

uint32_t dt_get_u32_prop(const char* device, const char* prop) {
    uint32_t rval = 0;
    uint32_t len = 0;
    dt_node_t* dev = dt_find(gDeviceTree, device);
    if (!dev) panic("invalid devicetree: no device!");
    uint32_t* val = dt_prop(dev, prop, &len);
    if (!val) panic("invalid devicetree: no prop!");
    memcpy(&rval, &val[0], 4);
    return rval;
}
uint64_t dt_get_u64_prop(const char* device, const char* prop) {
    uint64_t rval = 0;
    uint32_t len = 0;
    dt_node_t* dev = dt_find(gDeviceTree, device);
    if (!dev) panic("invalid devicetree: no device!");
    uint64_t* val = dt_prop(dev, prop, &len);
    if (!val) panic("invalid devicetree: no prop!");
    memcpy(&rval, &val[0], 8);
    return rval;
}
uint64_t dt_get_u64_prop_i(const char* device, const char* prop, uint32_t idx) {
    uint64_t rval = 0;
    uint32_t len = 0;
    dt_node_t* dev = dt_find(gDeviceTree, device);
    if (!dev) panic("invalid devicetree: no device!");
    uint64_t* val = dt_prop(dev, prop, &len);
    if (!val) panic("invalid devicetree: no prop!");
    memcpy(&rval, &val[idx], 8);
    return rval;
}
void* dt_get_prop(const char* device, const char* prop, uint32_t* size) {
    uint64_t rval = 0;
    uint32_t len = 0;
    dt_node_t* dev = dt_find(gDeviceTree, device);
    if (!dev) panic("invalid devicetree: no device!");
    uint64_t* val = dt_prop(dev, prop, &len);
    if (!val) panic("invalid devicetree: no prop!");
    if (size) *size = len;
    return val;
}

/*

    Lock:
    [  63:2 pointer to last task with ownership ][ 1: busy ][ 0: held ]

    If last task with ownership == current_task and busy, zero out last task with ownership and yield

*/

#define IS_LOCK_HELD(_lock) ((*(volatile lock*)_lock) & 1)
#define IS_LOCK_BUSY(_lock) ((*(volatile lock*)_lock) & 2)
#define GET_LOCK_LAST_OWNER(_lock) ((struct task*)((*(volatile lock*)_lock) & (~3)))
#define SET_LOCK_HELD(_lock) do { (*(volatile lock*)_lock) |= 1; } while (0)
#define SET_LOCK_BUSY(_lock) do { (*(volatile lock*)_lock) |= 2; } while (0)
#define SET_LOCK_NOT_HELD(_lock) do { (*(volatile lock*)_lock) &= ~1; } while (0)
#define SET_LOCK_NOT_BUSY(_lock) do { (*(volatile lock*)_lock) &= ~2; } while (0)
#define SET_LOCK_LAST_OWNER(_lock, _task) do { (*(volatile lock*)_lock) &= 3; (*(volatile lock*)_lock) |= ((uint64_t)_task) & (~3);  } while (0)

void lock_take(lock* _lock) {
    // takes a lock yielding until it acquires it
    while (1) {
        if (!IS_LOCK_HELD(_lock)) {
            disable_interrupts(); // this should be atomic rather than this but we're not multicore so whatev
            if (!IS_LOCK_HELD(_lock)) {
                if (GET_LOCK_LAST_OWNER(_lock) == task_current() && IS_LOCK_BUSY(_lock)) {
                    SET_LOCK_LAST_OWNER(_lock, 0);
                    task_yield_asserted();
                    continue;
                } else {
                    SET_LOCK_HELD(_lock);
                    SET_LOCK_NOT_BUSY(_lock);
                    SET_LOCK_LAST_OWNER(_lock, task_current());
                    enable_interrupts();
                    return;
                }
            }
            enable_interrupts();
        } else {
            if (!IS_LOCK_BUSY(_lock)) {
                disable_interrupts();
                SET_LOCK_BUSY(_lock);
                enable_interrupts();
            }
        }
        task_yield();
    }
} 
void lock_take_spin(lock* _lock) { 
    // takes a lock spinning until it acquires it
    while (1) {
        if (!IS_LOCK_HELD(_lock)) {
            disable_interrupts(); // this should be atomic rather than this but we're not multicore so whatev
            if (!IS_LOCK_HELD(_lock)) {
                SET_LOCK_HELD(_lock);
                SET_LOCK_NOT_BUSY(_lock);
                SET_LOCK_LAST_OWNER(_lock, task_current());
                enable_interrupts();
                return;
            }
            enable_interrupts();
        } else {
            if (!IS_LOCK_BUSY(_lock)) {
                disable_interrupts();
                SET_LOCK_BUSY(_lock);
                enable_interrupts();
            }
        }
    }

}
void lock_release(lock* _lock) {
    // releases ownership on a lock
    disable_interrupts(); // this should be atomic rather than this but we're not multicore so whatev
    SET_LOCK_NOT_HELD(_lock);
    SET_LOCK_LAST_OWNER(_lock, task_current());
    enable_interrupts();
}


