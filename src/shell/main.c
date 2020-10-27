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
uint32_t autoboot_count;
#define BOOT_FLAG_DEFAULT 0
#define BOOT_FLAG_HARD 1
#define BOOT_FLAG_HOOK 2
#define BOOT_FLAG_LINUX 3
#define BOOT_FLAG_RAW 4

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

/*

    Name: shell_main
    Description: shell main function

*/

void shell_main() {
    /*
        Load command handler
    */
    extern void task_list(const char *, char*);
    command_register("ps", "lists current tasks and irq handlers", task_list);
    command_register("ramdisk", "loads a ramdisk for xnu", ramdisk_cmd);
    command_register("bootr", "boot raw image", pongo_boot_raw);
    command_register("spin", "spins 1 second", pongo_spin);
    command_register("md8", "memory dump", md8_cmd);
    command_register("peek", "32bit mem read", peek_cmd);
    command_register("poke", "32bit mem write", poke_cmd);
    command_register("physdump", "dumps a page of phys", phys_page_dump);
    command_register("shell", "starts uart & usb based shell", start_host_shell);
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
