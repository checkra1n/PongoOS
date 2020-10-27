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

    Name: fdt_cmd
    Description: command handler for fdt

 */
extern void * fdt;
extern bool fdt_initialized;
#define LINUX_DTREE_SIZE 65536

void fdt_cmd() {
    if (!loader_xfer_recv_count) {
        iprintf("please upload a fdt before issuing this command\n");
        return;
    }
    if (fdt_initialized) free(fdt);
    fdt = malloc(LINUX_DTREE_SIZE);
    if (!fdt) panic("couldn't reserve heap for fdt");
    memcpy(fdt, loader_xfer_recv_data, loader_xfer_recv_count);
    fdt_initialized = 1;
    loader_xfer_recv_count = 0;
}

/*

    Name: pongo_boot_linux
    Description: command handler for bootl

*/

void pongo_boot_linux() {
    if (!linux_can_boot()) {
        printf("linux boot not prepared\n");
        return;
    }
    gBootFlag = BOOT_FLAG_LINUX;
    task_yield();
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
    command_register("bootl", "boots linux", pongo_boot_linux);
    command_register("bootr", "boot raw image", pongo_boot_raw);
    command_register("spin", "spins 1 second", pongo_spin);
    command_register("fdt", "load linux fdt from usb", fdt_cmd);
    command_register("shell", "starts uart & usb based shell", start_host_shell);
    usbloader_init();

    /*
        Load USB Loader
    */

    extern void modload_cmd();
    command_register("modload", "loads module", modload_cmd);
    disable_interrupts();
    command_init();
    event_wait_asserted(&command_handler_iter);
    
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
