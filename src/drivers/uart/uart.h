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
void serial_init();
void serial_early_init();
void serial_pinmux_init();
void serial_putc(char c);
void serial_disable_rx();
void serial_enable_rx();
void uart_flush();
void serial_teardown(void);

#ifdef UART_INTERNAL
#define rULCON0     (*(volatile uint32_t*)(gUartBase + 0x00))  //UART 0 Line control
#define rUCON0      (*(volatile uint32_t*)(gUartBase + 0x04))  //UART 0 Control
#define rUFCON0     (*(volatile uint32_t*)(gUartBase + 0x08))  //UART 0 FIFO control
#define rUMCON0     (*(volatile uint32_t*)(gUartBase + 0x0c))  //UART 0 Modem control
#define rUTRSTAT0   (*(volatile uint32_t*)(gUartBase + 0x10))  //UART 0 Tx/Rx status
#define rUERSTAT0   (*(volatile uint32_t*)(gUartBase + 0x14))  //UART 0 Rx error status
#define rUFSTAT0    (*(volatile uint32_t*)(gUartBase + 0x18))  //UART 0 FIFO status
#define rUMSTAT0    (*(volatile uint32_t*)(gUartBase + 0x1c))  //UART 0 Modem status
#define rUTXH0      (*(volatile uint32_t*)(gUartBase + 0x20))  //UART 0 Transmission Hold
#define rURXH0      (*(volatile uint32_t*)(gUartBase + 0x24))  //UART 0 Receive buffer
#define rUBRDIV0    (*(volatile uint32_t*)(gUartBase + 0x28))  //UART 0 Baud rate divisor
#define rUDIVSLOT0  (*(volatile uint32_t*)(gUartBase + 0x2C))  //UART 0 Baud rate divisor
#define rUINTM0     (*(volatile uint32_t*)(gUartBase + 0x38))  //UART 0 Baud rate divisor

#define rT8011RX    (*(volatile uint32_t*)(gGpioBase + 0x2A0))
#define rT8011TX    (*(volatile uint32_t*)(gGpioBase + 0x2A4))
#define UART_TX_MUX 0x8723A0
#define UART_RX_MUX 0x0763A0

extern uint64_t gUartBase;
#endif
