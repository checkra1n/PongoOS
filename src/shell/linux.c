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

extern volatile char gBootFlag;

/*

    Name: fdt_cmd
    Description: command handler for fdt

 */
extern void * fdt;
extern bool fdt_initialized;
extern char gLinuxCmdLine[LINUX_CMDLINE_SIZE];

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

void linux_cmdline_cmd(const char* cmd, char* args) {
    if (!*args) {
        iprintf("linux_cmdline usage: linux_cmdline [cmdline]\n");
        return;
    }

    size_t len = strlen(args);
    if (len > LINUX_CMDLINE_SIZE) {
        iprintf("Provided command line length is greater than LINUX_CMDLINE_SIZE (%lu > %lu)\n", len, (size_t) LINUX_CMDLINE_SIZE);
        return;
    }

    memcpy(gLinuxCmdLine, args, len);
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

void linux_commands_register() {
    command_register("bootl", "boots linux", pongo_boot_linux);
    command_register("linux_cmdline", "update linux kernel command line", linux_cmdline_cmd);
    command_register("fdt", "load linux fdt from usb", fdt_cmd);
}
