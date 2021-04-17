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
        uint32_t utrst = rUTRSTAT0;
        rUTRSTAT0 = utrst;
        if (utrst & 0x40) {
            (void)rURXH0; // force read
        } else
        if (utrst & 1) {
            int rxh0 = rURXH0;
            if (!uart_should_drop_rx) {
                char cmd_l = rxh0;
                enable_interrupts();
                queue_rx_char(cmd_l); // may take stdin lock
                disable_interrupts();
            }
        }
        uint32_t uerst = rUERSTAT0;
        rUERSTAT0 = uerst;
        enable_interrupts();
        task_exit_irq();
    }
}

static inline void put_serial_modifier(const char* str) {
    while (*str) serial_putc(*str++);
}

uint32_t orig_rUCON0, orig_rULCON0, orig_rUFCON0, orig_rUMCON0;
uint64_t gUartBase;
extern uint32_t gLogoBitmap[32];
void serial_early_init() {
    disable_interrupts();
    gUartBase = dt_get_u32_prop("uart0", "reg");
    gUartBase += gIOBase;
    orig_rUCON0  = rUCON0;
    orig_rULCON0 = rULCON0;
    orig_rUFCON0 = rUFCON0;
    orig_rUMCON0 = rUMCON0;
    rULCON0 = 3;
    rUCON0 = 0x405;
    rUFCON0 = 0;
    rUMCON0 = 0;
    char reorder[6] = {'1','3','2','6','4','5'};
    char modifier[] = {'\x1b', '[', '4', '1', ';', '1', 'm', 0};
    int cnt = 0;
    for (int y=0; y < 32; y++) {
        uint32_t b = gLogoBitmap[y];
        for (int x=0; x < 32; x++) {
            if (b & (1 << (x))) {
                modifier[3] = reorder[((cnt) % 6)];
                put_serial_modifier(modifier);
            }
            serial_putc(' ');
            serial_putc(' ');
            if (b & (1 << (x))) {
                put_serial_modifier("\x1b[0m");
            }
            cnt = (x+1) + y;
        }
        serial_putc('\n');
    }
    enable_interrupts();
}

void serial_pinmux_init() {
    // Pinmux debug UART on ATV4K
    // This will also pinmux uart0 on iPad Pro 2G
    if((strcmp(soc_name, "t8011") == 0)) {
        rT8011TX = UART_TX_MUX;
        rT8011RX = UART_RX_MUX;
    }
}

uint16_t uart_irq;
void serial_disable_rx() {
    uart_should_drop_rx = 1;
}
void serial_enable_rx() {
    uart_should_drop_rx = 0;
}
void serial_init() {
    struct task* irq_task = task_create_extended("uart", uart_main, TASK_IRQ_HANDLER|TASK_PREEMPT, 0);

    disable_interrupts();
    uart_irq = dt_get_u32_prop("uart0", "interrupts");
    serial_disable_rx();
    task_bind_to_irq(irq_task, uart_irq);
    rUCON0 = 0x5885;
    enable_interrupts();
}
void serial_teardown(void) {
    // Restore state set by iBoot
    rUCON0  = orig_rUCON0;
    rULCON0 = orig_rULCON0;
    rUFCON0 = orig_rUFCON0;
    rUMCON0 = orig_rUMCON0;
}
void serial_putc(char c) {
    if (c == '\n') serial_putc('\r');
    if (!gUartBase) return;
    while (!(rUTRSTAT0 & 0x04)) {}
    rUTXH0 = (unsigned)(c);
    return;
}
