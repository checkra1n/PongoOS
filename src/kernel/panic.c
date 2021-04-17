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
#include <errno.h>
#include <pongo.h>
#include <stdarg.h>
char preemption_over;

char panic_did_enter = 0;
void panic(const char* str, ...) {
    disable_interrupts();

    if (panic_did_enter) {
        iprintf("\ndouble panic: %s\n", str);
        while(1) {}
    }
    panic_did_enter = 1;
    preemption_over = 1;
    
    va_list va;
    va_start(va, str);
    iprintf("\npanic: ");
    viprintf(str, va);
    va_end(va);

    struct task *t = task_current();

    iprintf("\ncrashed task: ");
    if (t && t->name[0])
        puts(t->name);
    else puts("unknown");
    iprintf("\ncrashed process: ");
    if (t && t->proc && t->proc->name[0])
        puts(t->proc->name);
    else puts("unknown");
    int depth = 0;

    iprintf("\nCall stack:\n");
    uint64_t fpcopy[2];
    for(uint64_t *fp = __builtin_frame_address(0); fp; fp = (uint64_t*)fpcopy[0])
    {
        if (memcpy_trap(fpcopy, fp, 0x10) == 0x10) {
            iprintf("0x%016llx: fp 0x%016llx, lr 0x%016llx\n", ((uint64_t)fp), fpcopy[0], fpcopy[1]);
        } else {
            iprintf("couldn't access frame at %016llx, stopping here..,\n", (uint64_t)fp);
            break;
        }
        depth++;
        if (depth > 64) {
            iprintf("stack depth too large, stopping here...\n");
        }
   }

    sleep(5);
    wdt_reset();
}
