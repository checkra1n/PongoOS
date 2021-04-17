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

#define SYSCALL(name, handlerf) {.handler = handlerf, .sysc_name = name}
struct uap {
    uint64_t u64_arguments[7];
    uint64_t* state;
};
struct syscall_table {
    int (*handler)(struct task* task, struct uap* uap);
    char* sysc_name;
};

int sys_exit(struct task* task, struct uap* uap) {
    task_exit();
    return 0;
}

int sys_crash(struct task* task, struct uap* uap) {
    uap->state[0x100/8] = 0x41414141;
    return 0;
}

int sys_return(struct task* task, struct uap* uap) {
    return 0;
}

int sys_kmcrash(struct task* task, struct uap* uap) {
    *(uint32_t*)(0xbbadbeef) = 0x41424344;
    return 0;
}

struct syscall_table sysc_table[] = {
    SYSCALL("exit", sys_exit),
    SYSCALL("crash", sys_crash),
    SYSCALL("return", sys_return),
    SYSCALL("kmcrash", sys_kmcrash),
};


void pongo_syscall_entry(struct task* task, uint32_t sysnr, uint64_t* state) {
    enable_interrupts();
    bool is_valid_svc = false;
    if (sysnr == 0x42) {
        // pongo syscall
        uint32_t syscall_nr = state[15] & 0xffffffff;
        
        iprintf("-> got SVC 0x%x from task %s (%p)! syscall_nr = %d\n", sysnr, task->name, task, syscall_nr);
        struct uap uap;
        memcpy(uap.u64_arguments, state, 7 * 8);
        uap.state = state;
        
        if (syscall_nr == 0) {
            syscall_nr = state[0] & 0xffffffff;
            memcpy(uap.u64_arguments, &state[1], 7 * 8);
        }
        syscall_nr--;
        
        state[0] = -1;
        
        if (syscall_nr < (sizeof(sysc_table) / sizeof(struct syscall_table))) {
            if (sysc_table[syscall_nr].handler) {
                state[0] = sysc_table[syscall_nr].handler(task, &uap);
                is_valid_svc = true;
            }
        }
    }
    if (!is_valid_svc)
    {
        task_crash("bad syscall from task |%s|\n", task->name);
    }
    disable_interrupts();
}
