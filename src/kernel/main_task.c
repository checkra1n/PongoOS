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
#include <aes/aes_private.h>

boot_args * gBootArgs;
void* gEntryPoint;

#define BOOT_FLAG_DEFAULT 0
#define BOOT_FLAG_HARD 1
#define BOOT_FLAG_HOOK 2

extern volatile char gBootFlag;
dt_node_t *gDeviceTree;
uint64_t gIOBase;

void shell_main();

/*

    Name: pongo_main_task
    Description: main task handler

*/

void pongo_main_task()
{
    // Setup GPIO Base
    gpio_early_init();

    // Setup serial pinmux
    serial_pinmux_init();

    // Enable serial TX
    serial_early_init();

    // Turn on IRQ controller
    interrupt_init();

    // Enable IRQ serial RX
    serial_init();

    // Initialize pmgr
    pmgr_init();

    // Relieve WDT of its duty
    wdt_disable();

    // Set up AES
    aes_init();

    puts("");
    puts("#==================");
    puts("#");
    iprintf("# pongoOS " PONGO_VERSION " (EL%d)\n", get_el());
    puts("#");
    puts("# https://checkra.in");
    puts("#");
    puts("#==================");
    screen_mark_banner();
    iprintf("Booted by: %s\n", dt_get_prop("chosen", "firmware-version", NULL));
    strcpy(dt_get_prop("chosen", "firmware-version", NULL), "pongoOS-");
    strcat(dt_get_prop("chosen", "firmware-version", NULL), PONGO_VERSION);
    iprintf("Built with: GCC %s\n", __VERSION__);
    iprintf("Running on: %s\n", soc_name);

    shell_main();
}
