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
#import <pongo.h>


void tz_command() {
    volatile uint32_t* tz_regbase = (volatile uint32_t*)0x0000000200000480;

    iprintf("TZ0 (%s):\n\tbase: %x (%llx)\n\tend: %x (%llx)\n\nTZ1 (%s):\n\tbase: %x (%llx)\n\tend: %x (%llx)\n\n", tz_regbase[4] ? "locked" : "unlocked", tz_regbase[0], (((uint64_t)tz_regbase[0]) << 12) | 0x800000000ULL, tz_regbase[1], (((uint64_t)tz_regbase[1]) << 12) | 0x800000000ULL, tz_regbase[5] ? "locked" : "unlocked", tz_regbase[2], (((uint64_t)tz_regbase[2]) << 12) | 0x800000000ULL, tz_regbase[3], (((uint64_t)tz_regbase[3]) << 12) | 0x800000000ULL);
}

void tz_lockdown() {
    volatile uint32_t* tz_regbase = (volatile uint32_t*)0x0000000200000480;
    
    if (tz_regbase[0]) tz_regbase[4] = 1;
    if (tz_regbase[2]) tz_regbase[5] = 1;
}

bool tz_blackbird() {
    volatile uint32_t* tz_regbase = (volatile uint32_t*)0x0000000200000480;
    if (tz_regbase[4]) {
        iprintf("registers are locked\n");
        return false;
    }
    tz_regbase[0] ^= 0x100000;
    return true;
}
void tz0_set(const char* cmd, char* args) {
    if (! *args) {
        iprintf("tz_set usage: tz0_set [base] [end]\n");
        return;
    }
    char* arg1 = command_tokenize(args, 0x1ff - (args - cmd));
    if (!*arg1) {
        iprintf("tz_set usage: tz0_set [base] [end]\n");
        return;
    }
    uint64_t base = strtoull(args, NULL, 16);
    uint64_t end = strtoull(arg1, NULL, 16);
    volatile uint32_t* tz_regbase = (volatile uint32_t*)0x0000000200000480;
    if (tz_regbase[4]) {
        iprintf("registers are locked\n");
        return;
    }
    tz_regbase[0] = base;
    tz_regbase[1] = end;
}
void *tz0_calculate_encrypted_block_addr(uint64_t offset) {
    uint64_t offset_block = (offset & (~0x1f));
    offset_block <<= 1; // * 2
    
    return (void*)(0xc00000000ULL + offset_block);
}

void tz_setup() {
    command_register("tz", "trustzone info", tz_command);
    command_register("tz0_set", "change tz0 registers", (void*)tz0_set);
    command_register("tz_lockdown", "trustzone lockdown", (void*)tz_lockdown);
    command_register("tz_blackbird", "trustzone blackbird attack", (void*)tz_blackbird);
}
