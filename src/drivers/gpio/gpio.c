/*
 * pongoOS - https://checkra.in
 *
 * Copyright (C) 2019-2023 checkra1n team
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

void gpio_main(void) {
    while(1) {
        iprintf("gpio irq %x\n", task_current()->irq_type);
        task_exit_irq();
    }
}
struct task gpio_task = {.name = "gpio"};

uint64_t gGpioBase;
void gpio_early_init(void)
{
    gGpioBase = gIOBase + dt_get_u64("/arm-io/gpio", "reg", 0);
}

void gpio_init(void) {
    /*
    size_t len = 0;
    dt_node_t* buttons = dt_get("buttons");
    uint32_t* interrupts = dt_get_prop(buttons, "interrupts", &len);

    for (int i=0; i<len/4; i++) {
        task_register_irq(&gpio_task, gpio_main, interrupts[i]);
    }*/
}
