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
#include <stdio.h>
#include <sys/stat.h>
#include <pongo.h>

caddr_t _sbrk(int size) {
    return (caddr_t)alloc_contig(size);
}

int _fstat(int file, struct stat *st) {
    st->st_mode = S_IFCHR;
    return 0;
}

int _exit() {
   task_exit();
   return -1; // should never be reached, ever.
}

int _isatty(int file) { return 1; }
int _open(const char *name, int flags, int mode) { return -1; }
int _lseek(int file, int ptr, int dir) { return 0; }
int _close(int file) { return -1; }

char stdout_buf[STDOUT_BUFLEN];
int stdout_buf_len;
lock stdout_lock;

void fetch_stdoutbuf(char* to, int* len) {
    lock_take(&stdout_lock);
    memcpy(to, stdout_buf, stdout_buf_len);
    *len = stdout_buf_len;
    stdout_buf_len = 0;
    lock_release(&stdout_lock);
}

int _write(int file, char *ptr, int len) {
    lock_take(&stdout_lock);
    int i;
    for (i = 0; i < len; i++) {
        if (ptr[i] == '\0') serial_putc('\r');
        serial_putc(ptr[i]);
	    screen_putc(ptr[i]);
        
        if (stdout_buf_len == 511) { // non-blocking behavior
            memcpy(stdout_buf, stdout_buf+1, 510);
            stdout_buf_len = 510;
        }
        stdout_buf[stdout_buf_len++] = ptr[i];
        
    }
    lock_release(&stdout_lock);
    return len;
}


lock stdin_lock;
char stdin_buf[512];
struct event stdin_ev;
uint32_t bufoff = 0;
extern uint32_t uart_should_drop_rx;
void queue_rx_char(char inch) {
    lock_take(&stdin_lock);
    if (!uart_should_drop_rx)
        putchar(inch);
    if (bufoff < 512)
        stdin_buf[bufoff++] = inch;
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
