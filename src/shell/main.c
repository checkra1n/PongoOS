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
uint32_t autoboot_count;

extern volatile char gBootFlag;


/*

    Name: pongo_boot_raw
    Description: command handler for bootr

*/

void pongo_boot_raw() {
    if (!loader_xfer_recv_count) {
        iprintf("please upload a raw image before issuing this command\n");
        return;
    }
    loader_xfer_recv_count = 0;
    gBootFlag = BOOT_FLAG_RAW;
    task_yield();
}

void* ramdisk_buf;
uint32_t ramdisk_size;

/*

    Name: ramdisk_cmd
    Description: command handler for ramdisk

 */

void ramdisk_cmd() {
    if (!loader_xfer_recv_count) {
        iprintf("please upload a ramdisk before issuing this command\n");
        return;
    }
    if (ramdisk_buf) free(ramdisk_buf);
    ramdisk_buf = malloc(loader_xfer_recv_count);
    if (!ramdisk_buf) panic("couldn't reserve heap for ramdisk");
    ramdisk_size = loader_xfer_recv_count;
    memcpy(ramdisk_buf, loader_xfer_recv_data, ramdisk_size);
    loader_xfer_recv_count = 0;
}

/*

    Name: pongo_spin
    Description: command handler for spin

*/

void pongo_spin() {
    spin(1000000);
}

extern char is_masking_autoboot;
void start_host_shell() {
    task_current()->flags |= TASK_CAN_EXIT;

    is_masking_autoboot = 1;
    command_unregister("shell");
    command_unregister("autoboot");
    serial_enable_rx();
    screen_puts("Enabling USB");
    usb_init();
    screen_puts("Done!");
}
#define HEXDUMP_COLS 16
void hexdump(void *mem, unsigned int len)
{
        unsigned int i;

        for(i = 0; i < len + ((len % HEXDUMP_COLS) ? (HEXDUMP_COLS - len % HEXDUMP_COLS) : 0); i++)
        {
                /* print offset */
                if(i % HEXDUMP_COLS == 0)
                {
                        iprintf("0x%09llx: ", (((uint64_t)mem)+i));
                }

                /* print hex data */
                if(i < len)
                {
                        iprintf("%02x ", 0xFF & ((char*)mem)[i]);
                }
                else /* end of block, just aligning for ASCII dump */
                {
                        iprintf("   ");
                }

                if(i % HEXDUMP_COLS == (HEXDUMP_COLS - 1))
                {
                        iprintf("\n");
                }
        }
}

void md8_cmd(const char* cmd, char* args) {
    uint64_t base = strtoull(args, NULL, 16);
    uint64_t size = 0x20;
    char* arg1 = command_tokenize(args, 0x1ff - (args - cmd));
    if (arg1) {
        size = strtoull(arg1, NULL, 16);
    }

    if (!size || !base) {
        iprintf("md8 usage: md8 [base] [size]\n");
        return;
    }

    hexdump((void*)base, size);
}
void phys_page_dump(const char* cmd, char* args) {
    uint64_t base = strtoull(args, NULL, 16);

    if (! *args) {
        iprintf("physdump usage: physdump [base]\n");
        return;
    }
    map_range(0xc10000000, base, 0x4000, 3, 0, true);

    hexdump((void*)0xc10000000, 0x4000);
}
void peek_cmd(const char* cmd, char* args) {
    if (! *args) {
        iprintf("peek usage: peek [addr]\n");
        return;
    }

    uint64_t addr = strtoull(args, NULL, 16);
    uint32_t rv = *((uint32_t*)addr);
    iprintf("0x%llx: %x (%x %x %x %x)\n", (uint64_t)addr, rv, rv&0xff, (rv>>8)&0xff, (rv>>16)&0xff, (rv>>24)&0xff);
}
void poke_cmd(const char* cmd, char* args) {
    if (! *args) {
        iprintf("poke usage: poke [addr] [val32]\n");
        return;
    }
    char* arg1 = command_tokenize(args, 0x1ff - (args - cmd));
    if (!*arg1) {
        iprintf("poke usage: poke [addr] [val32]\n");
        return;
    }
    uint64_t addr = strtoull(args, NULL, 16);
    uint32_t value = strtoul(arg1, NULL, 16);
    iprintf("writing %x @ 0x%llx\n", value, addr);
    *((uint32_t*)addr) = value;
}

void panic_cmd(const char* cmd, char* args) {
    if (! *args) {
        panic("panic called from shell");
    } else {
        panic("%s", args);
    }
}

void spawn_cmd(const char* cmd, char* args) {
    if (! *args) {
        iprintf("usage: spawn syscallnr [x0]\n");
        return;
    }
    char* arg1 = command_tokenize(args, 0x1ff - (args - cmd));

    uint64_t sysc = strtoull(args, NULL, 16);

    uint64_t shc_addr = 0;

    struct proc* umproc = proc_create(NULL, "usermode", 0);
    vm_allocate(umproc->vm_space, &shc_addr, 0x4000, VM_FLAGS_ANYWHERE | VM_FLAGS_NOMAP);
    uint64_t phys = ppage_alloc();
    uint32_t* ins = phystokv(phys);
    int ic = 0;
    ins[ic++] = 0xa9bf7bfd;
    ins[ic++] = 0xd4000841;
    ins[ic++] = 0xd280002f;
    ins[ic++] = 0xd4000841;
    ins[ic++] = 0xa8c17bfd;
    ins[ic++] = 0xd65f03c0;

    invalidate_icache();
    vm_space_map_page_physical_prot(umproc->vm_space, shc_addr, phys, PROT_READ | PROT_WRITE | PROT_EXEC);

    struct task* umtask = proc_create_task(umproc, (void*)shc_addr);

    if (arg1)
        umtask->initial_state[0] = strtoull(arg1, NULL, 16);

    umtask->initial_state[15] = sysc;

    task_link(umtask); // implicitly consumes the reference (ie. once the task exits, it will drop the last reference and get free'd)

    proc_release(umproc); // the proc will be held alive by the reference in the task, which will be dropped once it gets free'd
}

void paging_cmd(const char* cmd, char* args) {
    uint64_t addr = 0;
    vm_allocate(task_current()->vm_space, &addr, 0x8000, VM_FLAGS_ANYWHERE);
    *(uint32_t*)(addr + 0x3ffe) = 0x41414141;
    iprintf("fault-in successful!\n");
}
int recurse_me(int x) { // we need some actual code or the compiler will optimize this out
    int rv = 0;
    if (x & 1)
        rv += recurse_me(x + 2);
    iprintf("pls do not optimise me out: %d\n", rv); // side-effecting, reads rv, which depends on actually recursing on recurse_times
    return rv;
}
void recursion_cmd(const char* cmd, char* args) {
    recurse_me(10001);
}

/*

    Name: shell_main
    Description: shell main function

*/

void shell_main() {
    /*
        Load command handler
    */

    extern void task_list(const char *, char*);
    command_register("panic", "calls panic()", panic_cmd);
    command_register("ps", "lists current tasks and irq handlers", task_list);
    command_register("ramdisk", "loads a ramdisk for xnu or linux", ramdisk_cmd);
    command_register("bootr", "boot raw image", pongo_boot_raw);
    command_register("spin", "spins 1 second", pongo_spin);
    command_register("md8", "memory dump", md8_cmd);
    command_register("peek", "32bit mem read", peek_cmd);
    command_register("poke", "32bit mem write", poke_cmd);
    command_register("physdump", "dumps a page of phys", phys_page_dump);
    command_register("shell", "starts uart & usb based shell", start_host_shell);
    command_register("spawn", "starts a usermode process", spawn_cmd);
    command_register("paging", "tests paging", paging_cmd);
    command_register("recursion", "tests stack guards", recursion_cmd);
    extern void linux_commands_register(void);
    linux_commands_register();
    usbloader_init();

    /*
        Load USB Loader
    */

    extern void modload_cmd();
    command_register("modload", "loads module", modload_cmd);
    command_init();

    xnu_init();

#ifdef AUTOBOOT
    extern void pongo_autoboot();
    pongo_autoboot();
#endif

    queue_rx_string("shell\n");

#ifdef LOCK_TESTING
    task_register(&pongo_lock_test1, pongo_lock_test1_entry);
    task_register(&pongo_lock_test2, pongo_lock_test2_entry);
#endif
//    gBootFlag = BOOT_FLAG_HOOK;
}
