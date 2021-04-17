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
#define strcpy strcpy_
#define memcpy memcpy_
#define strcmp strcmp_
#define strlen strlen_

char* strcpy_(char* to, const char* from)
{
    char cur = 0;
    while ((cur = (*from++)))
        *to++ = cur;
    *to++ = 0;
    return to; // i know this is not up to spec but who uses the return value of strcpy anyway lmao
}

void* memcpy_(void* dst, const void* src, unsigned long n)
{
    while (n) {
        *(char*)dst++ = *(char*)src++;
        n--;
    }
    return dst; // i know this is not up to spec but who uses the return value of memcpy anyway lmao
}

int strcmp_(const char* s1, const char* s2)
{
    while (*s1 && (*s1 == *s2))
        s1++, s2++;
    return *(const unsigned char*)s1 - *(const unsigned char*)s2;
}

unsigned long strlen_(const char* str)
{
    unsigned long rv = 0;
    while (*str++)
        rv++;
    return rv;
}

