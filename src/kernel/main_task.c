/*
 * pongoOS - https://checkra.in
 *
 * Copyright (C) 2019-2020 checkra1n team
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
#include <aes/aes_private.h>

boot_args * gBootArgs;
void* gEntryPoint;

extern volatile char gBootFlag;
dt_node_t *gDeviceTree;
uint64_t gIOBase;

void shell_main();

/*

    Name: pongo_main_task
    Description: main task handler

*/

uint64_t gBootTimeTicks;
void pongo_main_task() {
    if (!socnum) {
        iprintf("unknown platform: %s, will likely crash soon...\n", soc_name);
    }
    
    gBootTimeTicks = get_ticks();
    
    // Setup HAL
    hal_init();

    // Setup GPIO Base
    gpio_early_init();

    // Setup serial pinmux
    serial_pinmux_init();

    // Enable serial TX
    serial_early_init();

    // Enable IRQ serial RX
    serial_init();

    /*
        Initialize display
     */
    mipi_init();

    /*
        Initialize TrustZone drivers
     */
    tz_setup();

    // Relieve WDT of its duty
    wdt_disable();

    // Set up AES
    aes_init();

    fb_reset_cursor();
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
#ifdef __clang__
    iprintf("Built with: Clang %s\n", __clang_version__);
#else
    iprintf("Built with: GCC %s\n", __VERSION__);
#endif
    iprintf("Running on: %s\n", hal_platform_name());

    shell_main();
}
