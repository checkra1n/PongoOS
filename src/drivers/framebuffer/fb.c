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
#include "font8x8_basic.h"

uint32_t* gFramebuffer;
uint32_t* gFramebufferCopy;
uint32_t gWidth;
uint32_t gHeight;
uint32_t gRowPixels;
uint32_t y_cursor;
uint32_t x_cursor;
uint8_t scale_factor;
uint32_t bannerHeight = 0;
char overflow_mode = 0;
uint32_t basecolor = 0x41414141;
void screen_fill(uint32_t color) {
    for (int y = 0; y < gHeight; y++) {
        for (int x = 0; x < gWidth; x++) {
            gFramebuffer[x + y * gRowPixels] = color;
        }
    }
    cache_clean(gFramebuffer, gHeight * gRowPixels * 4);
}
void screen_fill_basecolor() {
    return screen_fill(basecolor);
}
void screen_clear_all()
{
    y_cursor = bannerHeight;
    for (int y = bannerHeight; y < gHeight; y++) {
        for (int x = 0; x < gWidth; x++) {
            gFramebuffer[x + y * gRowPixels] = gFramebufferCopy[x + y * gRowPixels];
        }
    }
    cache_clean(gFramebuffer, gHeight * gRowPixels * 4);
}
void screen_clear_row()
{
    for (int y = 0; y < (1 + 8 * SCALE_FACTOR); y++) {
        for (int x = 0; x < gWidth; x++) {
            gFramebuffer[x + ((y + y_cursor) * gRowPixels)] = gFramebufferCopy[x + ((y + y_cursor) * gRowPixels)];
        }
    }
    cache_clean(&gFramebuffer[y_cursor * gRowPixels], (1 + 8 * SCALE_FACTOR) * gRowPixels * 4);
}
uint32_t color_compose(uint16_t components[3]) {
    return ((((uint32_t)components[3]) & 0xff) << 24) | ((((uint32_t)components[2]) & 0xff) << 16) | ((((uint32_t)components[1]) & 0xff) << 8)  | ((((uint32_t)components[0]) & 0xff) << 0); // works on ARGB8,8,8,8 only, i'll add ARGB5,9,9,9 eventually
}
uint32_t color_compose_v32(uint32_t components[3]) {
    return ((((uint32_t)components[3]) & 0xff) << 24) | ((((uint32_t)components[2]) & 0xff) << 16) | ((((uint32_t)components[1]) & 0xff) << 8)  | ((((uint32_t)components[0]) & 0xff) << 0); // works on ARGB8,8,8,8 only, i'll add ARGB5,9,9,9 eventually
}
void color_decompose(uint32_t color, uint16_t* components) {
    components[0] = color & 0xff;
    components[1] = (color >> 8) & 0xff;
    components[2] = (color >> 16) & 0xff;
    components[3] = (color >> 24) & 0xff;
}
uint16_t component_darken(float component, float factor) {
    float mul = (component * factor);
    uint32_t mulr = mul;
    if (mulr > 0xff) return 0xff; // clamp to 0xff as max (only works on ARGB8,8,8,8, will fix later)
    return mulr;
}
uint32_t color_darken(uint32_t color, float darkenfactor) {
    uint16_t components[4];
    color_decompose(color, components);
    components[0] = component_darken(components[0], darkenfactor);
    components[1] = component_darken(components[1], darkenfactor);
    components[2] = component_darken(components[2], darkenfactor);
    return color_compose(components);
}
uint32_t colors_average(uint32_t color1, uint32_t color2) {
    uint16_t components[4];
    uint16_t components1[4];
    color_decompose(color1, components);
    color_decompose(color2, components1);
    components[0] = (components[0] + components1[0]) >> 1;
    components[1] = (components[1] + components1[1]) >> 1;
    components[2] = (components[2] + components1[2]) >> 1;
    return color_compose(components);
}

uint32_t colors_mix_alpha(uint32_t color1, uint32_t color2) {
    uint16_t components[4];
    uint16_t components1[4];
    uint32_t componentsw[4];
    color_decompose(color1, components);
    color_decompose(color2, components1);
    componentsw[0] = (components[0] * components[3]);
    componentsw[1] = (components[1] * components[3]);
    componentsw[2] = (components[2] * components[3]);
    componentsw[0] += (components1[0] * components1[3]);
    componentsw[1] += (components1[1] * components1[3]);
    componentsw[2] += (components1[2] * components1[3]);
    uint32_t total_alpha = components[3] + components1[3];
    componentsw[0] /= total_alpha;
    componentsw[1] /= total_alpha;
    componentsw[2] /= total_alpha;
    componentsw[3] = 0xff;
    
    return color_compose_v32(componentsw);
}

void screen_putc(uint8_t c)
{
    if (!gFramebuffer) return;
    disable_interrupts();
    if (c == '\b') {
        if (x_cursor > 8 * SCALE_FACTOR) {
            x_cursor -= 8 * SCALE_FACTOR;
        } else {
            x_cursor = 0;
        }
        if (LEFT_MARGIN > x_cursor) {
            x_cursor = LEFT_MARGIN;
        }
        enable_interrupts();
        return;
    }
    if (c == '\n' || (x_cursor + (8 * SCALE_FACTOR)) > (gWidth - LEFT_MARGIN*2)) {
        if ((y_cursor + (12 * SCALE_FACTOR) + 16) > gHeight) {
            y_cursor = bannerHeight;
        } else {
            y_cursor += 1 + 8 * SCALE_FACTOR;
        }
        x_cursor = LEFT_MARGIN;
        screen_clear_row();
    }
    if (c == '\n') {
        enable_interrupts();
        return;
    }
    if (c == '\r') {
        x_cursor = LEFT_MARGIN;
        screen_clear_row();
        enable_interrupts();
        return;
    }
    x_cursor += 8 * SCALE_FACTOR;
    volatile uint32_t local_x_cursor = x_cursor;
    volatile uint32_t local_y_cursor = y_cursor;

    enable_interrupts();
    // @squiffy, whenever you'll see this: tbt libmoonshine
    for (int x = 0; x < (8 * SCALE_FACTOR); x++) {
        for (int y = 0; y < (8 * SCALE_FACTOR); y++) {
            if (font8x8_basic[c & 0x7f][y / SCALE_FACTOR] & (1 << (x / SCALE_FACTOR))) {
                uint32_t ind = (x + local_x_cursor) + ((y + local_y_cursor) * gRowPixels);
                uint32_t curcolor = basecolor;
                curcolor ^= 0xFFFFFFFF;
                gFramebuffer[ind] = curcolor;
            } else {
                uint32_t ind = (x + local_x_cursor) + ((y + local_y_cursor) * gRowPixels);
                uint32_t rcol = gFramebufferCopy[ind];
                gFramebuffer[ind] = colors_average(rcol, basecolor);
            }
        }
    }
    cache_clean(&gFramebuffer[y_cursor * gRowPixels], (1 + 8 * SCALE_FACTOR) * gRowPixels * 4);
}
void screen_write(const char* str)
{
    while (*str)
        screen_putc(*str++);
}
void screen_puts(const char* str)
{
    screen_write(str);
    screen_putc('\n');
}
void screen_mark_banner() {
    bannerHeight = y_cursor;
}

void screen_invert() {
    for (int y = 0; y < gHeight; y++) {
        for (int x = 0; x < gWidth; x++) {
            gFramebuffer[x + y * gRowPixels] ^= 0xffffffff;
            gFramebufferCopy[x + y * gRowPixels] ^= 0xffffffff;
        }
    }
    basecolor ^= 0xffffffff;
    cache_clean(gFramebuffer, gHeight * gRowPixels * 4);
}

uint32_t gLogoBitmap[32] = { 0x0, 0xa00, 0x400, 0x5540, 0x7fc0, 0x3f80, 0x3f80, 0x1f00, 0x1f00, 0x1f00, 0x3f80, 0xffe0, 0x3f80, 0x3f80, 0x3f83, 0x103f9f, 0x18103ffb, 0xe3fffd5, 0x1beabfab, 0x480d7fd5, 0xf80abfab, 0x480d7fd5, 0x1beabfab, 0xe3fffd5, 0x18107ffb, 0x107fdf, 0x7fc3, 0xffe0, 0xffe0, 0xffe0, 0x1fff0, 0x1fff0 };

void screen_init() {
    gRowPixels = gBootArgs->Video.v_rowBytes >> 2;
    uint16_t width = gWidth = gBootArgs->Video.v_width;
    uint16_t height = gHeight = gBootArgs->Video.v_height;
    uint64_t fbbase = gBootArgs->Video.v_baseAddr;
    uint64_t fbsize = gHeight * gRowPixels * 4;
    uint64_t fboff;
    if(is_16k())
    {
        fboff  = fbbase & 0x3fffULL;
        fbsize = (fbsize + fboff + 0x3fffULL) & ~0x3fffULL;
    }
    else
    {
        fboff  = fbbase & 0xfffULL;
        fbsize = (fbsize + fboff + 0xfffULL) & ~0xfffULL;
    }
    map_range(0xfb0000000ULL, fbbase - fboff, fbsize, 3, 1, true);
    gFramebuffer = (uint32_t*)(0xfb0000000ULL + fboff);
    gFramebufferCopy = (uint32_t*)alloc_contig(fbsize);

    height &= 0xfff0;
    scale_factor = 2;
    if (width > 800)
        scale_factor = 3;

    if (width > height) scale_factor = 1;

    uint32_t logo_scaler_factor = 2 * scale_factor;
    if (socnum == 0x8012) logo_scaler_factor = 1;

    uint32_t logo_x_begin = (gRowPixels / 2) - (16 * logo_scaler_factor);
    uint32_t logo_y_begin = (height / 2) - (16 * logo_scaler_factor);

    for (uint32_t y = 0; y < (32 * logo_scaler_factor); ++y) {
        uint32_t b = gLogoBitmap[y / logo_scaler_factor];
        for (uint32_t x = 0; x < (32 * logo_scaler_factor); ++x) {
            uint32_t ind = logo_x_begin + x + ((logo_y_begin + y) * gRowPixels);
            uint32_t curcolor = gFramebuffer[ind];
            if (b & (1 << (x / logo_scaler_factor))) {
                curcolor ^= 0xFFFFFFFF;
            }
            gFramebuffer[ind] = curcolor;
        }
    }
    
    memcpy(gFramebufferCopy, gFramebuffer, fbsize);

    basecolor = gFramebuffer[0];
    cache_clean(gFramebuffer, gHeight * gRowPixels * 4);
    command_register("fbclear", "clears the framebuffer output (minus banner)", screen_clear_all);
    command_register("fbinvert", "inverts framebuffer contents", screen_invert);
    scale_factor = 1;
}
