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
#ifndef AES_H
#define AES_H

#include <stddef.h>
#include <stdint.h>

#define AES_ALL_MASK (AES_MODE_MASK | AES_CIPHER_MASK | AES_BITS_MASK | AES_KEY_MASK)

#define AES_ENCRYPT     0x00000000
#define AES_DECRYPT     0x80000000
#define AES_MODE_MASK   0x80000000

#define AES_CBC         0x00000000
#define AES_ECB         0x40000000
#define AES_CIPHER_MASK 0x40000000

#define AES_128         0x10000000
#define AES_192         0x20000000
#define AES_256         0x30000000
#define AES_BITS_MASK   0x30000000

#define AES_USER_KEY    0x00000000
#define AES_UID         0x00000001
#define AES_GID0        0x00000002
#define AES_GID1        0x00000003
#define AES_KEY_MASK    0x00000003

// Return value of 0 = success.
// Any other return value is an error from <errno.h>.
int aes(uint32_t op, const void *src, void *dst, size_t len, const void *iv, const void *key);

#endif
