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
#include <stdint.h>

#define SCALE_FACTOR scale_factor
#define LEFT_MARGIN 4 * scale_factor

extern char overflow_mode;
extern uint32_t* gFramebuffer;
extern uint32_t gWidth;
extern uint32_t gHeight;
extern uint32_t gRowPixels;
extern uint32_t y_cursor;
extern uint32_t x_cursor;
extern uint8_t scale_factor;

void screen_init();
void screen_puts(const char* str);
void screen_write(const char* str);
void screen_putc(uint8_t c);
void screen_clear_row();
void screen_mark_banner();
void screen_fill_basecolor();
void screen_fill(uint32_t color);
