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
#include <stdio.h>
#include <sys/stat.h>
#include <pongo.h>

int _fstat(int file, struct stat *st) {
    st->st_mode = S_IFCHR;
    return 0;
}

int _isatty(int file) { return 1; }
int _open(const char *name, int flags, int mode) { return -1; }
int _lseek(int file, int ptr, int dir) { return 0; }
int _close(int file) { return -1; }

static char stdout_buf[STDOUT_BUFLEN];
static volatile int stdout_buf_len;
static volatile bool stdout_blocking;
static lock stdout_lock;

extern char preemption_over;

void set_stdout_blocking(bool block)
{
    lock_take(&stdout_lock);
    stdout_blocking = block;
    lock_release(&stdout_lock);
}

void fetch_stdoutbuf(char* to, int* len) {
    lock_take(&stdout_lock);
    memcpy(to, stdout_buf, stdout_buf_len);
    *len = stdout_buf_len;
    stdout_buf_len = 0;
    lock_release(&stdout_lock);
}

int _write(int file, char *ptr, int len)
{
    switch(file)
    {
        case 1: if (preemption_over) file = 2;
        case 2: break;
        default: panic("Write to unknown fd: %d", file);
    }
    if(file == 1) {
        extern uint64_t dis_int_count;
        if (dis_int_count != 0) {
            panic("write() to stdout with interrupts disabled - please use stderr instead\n");
        }
        lock_take(&stdout_lock);
    }
    int i;
    for(i = 0; i < len; i++)
    {
        if (ptr[i] == '\0') serial_putc('\r');
        serial_putc(ptr[i]);
        screen_putc(ptr[i]);

        if(file != 1) continue;

    retry:;
        if(stdout_buf_len >= STDOUT_BUFLEN - 1)
        {
            if(stdout_blocking) // blocking
            {
                lock_release(&stdout_lock);
                task_yield();
                lock_take(&stdout_lock);
                goto retry;
            }
            else // non-blocking = discard
            {
                --stdout_buf_len;
                memmove(stdout_buf, stdout_buf+1, stdout_buf_len);
            }
        }
        stdout_buf[stdout_buf_len++] = ptr[i];
    }
    if(file == 1) lock_release(&stdout_lock);
    return len;
}


lock stdin_lock;
char stdin_buf[512];
struct event stdin_ev;
uint32_t bufoff = 0;
extern uint32_t uart_should_drop_rx;
void queue_rx_char(char inch) {
    lock_take(&stdin_lock);
    if (inch == '\x7f') {
        if (bufoff) {
            bufoff--;
            stdin_buf[bufoff] = 0;
            putc('\b', stderr);
            putc(' ', stderr);
            putc('\b', stderr);
            fflush(stderr);
        }
        lock_release(&stdin_lock);
        return;
    }
    if (!uart_should_drop_rx) {
        putc(inch, stderr);
        fflush(stderr);
    }
    if (bufoff < 512)
        stdin_buf[bufoff++] = inch;
    if (inch == '\n')
        event_fire(&stdin_ev);
    lock_release(&stdin_lock);
}
void queue_rx_string(char* string) {
    while (*string) queue_rx_char(*string++);
}
int _read(int file, char *ptr, int len) {
    if (!len) return len;
    int readln = 0;
    lock_take(&stdin_lock);
    while (!bufoff) {
        lock_release(&stdin_lock);
        event_wait(&stdin_ev);
        lock_take(&stdin_lock);
    }
    if (bufoff) {
        // 1. calculate memcpy length (l o l signedness)
        if (bufoff > len) readln = len;
        else if (bufoff == len) readln = bufoff;
        else if (bufoff < len) readln = bufoff;
        else panic("_read: shouldn't be reachable!");
        // 2. perform memcpy
        memcpy(ptr, stdin_buf, readln);
        // 3. update buffer in case of under-read
        if (bufoff > len) {
            memcpy(stdin_buf, stdin_buf+len, bufoff - readln);
        }
        bufoff -= readln;
    } else panic("_read: shouldn't be reachable!");
    lock_release(&stdin_lock);
    return readln;
}
