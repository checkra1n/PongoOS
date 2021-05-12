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
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <pongo.h>

int hexparse(uint8_t *buf, char *s, size_t len)
{
    for(size_t i = 0; i < len; ++i)
    {
        char c = s[2*i],
             d = s[2*i+1];
        if(!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) ||
           !((d >= '0' && d <= '9') || (d >= 'a' && d <= 'f') || (d >= 'A' && d <= 'F')))
        {
            return -1;
        }
        buf[i] = ((uint8_t)(c >= '0' && c <= '9' ? c - '0' : (c >= 'a' && c <= 'f' ? c - 'a' : c - 'A') + 10) << 4) |
                  (uint8_t)(d >= '0' && d <= '9' ? d - '0' : (d >= 'a' && d <= 'f' ? d - 'a' : d - 'A') + 10);
    }
    return 0;
}

void hexprint(uint8_t *data, size_t sz)
{
    char buf[0x61];
    for(size_t i = 0; i < sz; i += 0x30)
    {
        size_t max = sz - i > 0x30 ? 0x30 : sz - i;
        for(size_t j = 0; j < max; ++j)
        {
            uint8_t u  = data[i+j],
                    hi = (u >> 4) & 0xf,
                    lo =  u       & 0xf;
            buf[2*j]   = hi < 10 ? '0' + hi : 'a' + (hi - 10);
            buf[2*j+1] = lo < 10 ? '0' + lo : 'a' + (lo - 10);
        }
        buf[2*max] = '\0';
        iprintf("%s", buf);
    }
    iprintf("\n");
}
