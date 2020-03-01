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
#define UART_INTERNAL 1
#include <pongo.h>

char uart_queue[64];
uint8_t uart_queue_idx;
void uart_flush() {
    if (!uart_queue_idx) return;
    int local_queue_idx = 0;
    while (rUTRSTAT0 & 0x04)
    {
        if (local_queue_idx == uart_queue_idx) break;
        rUTXH0 = (unsigned)(uart_queue[local_queue_idx]);
        local_queue_idx++;
    }
    if (!local_queue_idx) return;

    if (local_queue_idx != uart_queue_idx) {
        memcpy(&uart_queue[0], &uart_queue[local_queue_idx], uart_queue_idx - local_queue_idx);
    }
    uart_queue_idx -= local_queue_idx;
}
void uart_force_flush() {
    for (int i = 0; i < uart_queue_idx; i++) {
        while (!(rUTRSTAT0 & 0x04)) {}
        rUTXH0 = (unsigned)(uart_queue[i]);
    }
    uart_queue_idx = 0;
}
void uart_update_tx_irq() {
    return;
    if (!uart_queue_idx)
        rUCON0 = 0x5885;
    else
        rUCON0 = 0x5F85;
}
uint32_t uart_should_drop_rx;
extern void queue_rx_char(char inch);
void uart_main() {
    while(1) {
        disable_interrupts();
        volatile uint32_t utrst = rUTRSTAT0;
        rUTRSTAT0 = utrst;
        if (utrst & 0x40) {
            volatile uint32_t noop = rURXH0;
        } else
        if (utrst & 1) {
            int rxh0 = rURXH0;
            if (!uart_should_drop_rx) {
                char cmd_l = rxh0;
                enable_interrupts();
                queue_rx_char(cmd_l);
                disable_interrupts();
            }
        }
        volatile uint32_t uerst = rUERSTAT0;
        rUERSTAT0 = uerst;
        uart_update_tx_irq();
        enable_interrupts();
        task_exit_irq();
    }
}
struct task uart_task = {.name = "uart"};

uint64_t gUartBase;
void serial_early_init() {
    disable_interrupts();
    gUartBase = dt_get_u32_prop("uart0", "reg");
    gUartBase += gIOBase;
    rULCON0 = 3;
    rUCON0 = 0x405;
    rUFCON0 = 0;
    rUMCON0 = 0;
    enable_interrupts();
}

uint16_t uart_irq;
void serial_disable_rx() {
    uart_should_drop_rx = 1;
}
void serial_enable_rx() {
    uart_should_drop_rx = 0;
}
char uart_irq_driven = 0;
void serial_init() {
    disable_interrupts();
    uart_irq = dt_get_u32_prop("uart0", "interrupts");
    serial_disable_rx();
    task_register_preempt_irq(&uart_task, uart_main, uart_irq);
    uart_irq_driven = 0;
    rUCON0 = 0x5885;
    enable_interrupts();
}
void serial_putc(char c) {
    if (c == '\n') serial_putc('\r');
    if (!gUartBase) return;
    while (!(rUTRSTAT0 & 0x04)) {}
    rUTXH0 = (unsigned)(c);
    return;
}
