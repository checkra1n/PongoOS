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
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <pongo.h>

#include "aes.h"
#include "aes_private.h"

static uintptr_t gAESBase;
static uint64_t gAESClockAddr;

#define rAES_CTL            *(volatile uint32_t*)(gAESBase + 0x008)
#define rAES_IN_STS         *(volatile uint32_t*)(gAESBase + 0x00c)
#define rAES_INPUT(n)       *(volatile uint32_t*)(gAESBase + 0x040 + ((n) << 2))
#define rAES_OUT_STS        *(volatile uint32_t*)(gAESBase + 0x050)
#define rAES_OUTPUT(n)      *(volatile uint32_t*)(gAESBase + 0x080 + ((n) << 2))
#define rAES_KEY_CTL        *(volatile uint32_t*)(gAESBase + 0x090)
#define rAES_KEY_WORD(n)    *(volatile uint32_t*)(gAESBase + 0x0c0 + ((n) << 2))
#define rAES_IV_CTL         *(volatile uint32_t*)(gAESBase + 0x0e0)
#define rAES_IV_WORD(n)     *(volatile uint32_t*)(gAESBase + 0x100 + ((n) << 2))

void aes_a7_init(void)
{
    gAESBase = gIOBase + 0x0a108000;
    switch(socnum)
    {
        case 0x8960:
            gAESClockAddr = gIOBase + 0x0e020100;
            break;
        case 0x7000:
        case 0x7001:
            gAESClockAddr = gIOBase + 0x0e0201e8;
            break;
        default:
            panic("AES A7: counterfeit init call");
    }
}

int aes_a7(uint32_t op, const void *src, void *dst, size_t len, const void *iv, const void *key)
{
    if(len < 0x10 || (len & 0xf))
    {
        panic("AES A7: Invalid data length");
    }
    const uint32_t *u32_key = key,
                   *u32_iv  = iv,
                   *u32_src = src;
    uint32_t *u32_dst = dst;
    uint32_t keyid, bits, encrypt, mode;
    switch(op & AES_KEY_MASK)
    {
        case AES_USER_KEY: keyid = 0; break;
        case AES_UID:      keyid = 1; break;
        case AES_GID0:     keyid = 2; break;
        case AES_GID1:     keyid = 3; break;
        // Add default case if we ever change key mask
    }
    switch(op & AES_BITS_MASK)
    {
        case AES_128: bits = 0; break;
        case AES_192: bits = 1; break;
        case AES_256: bits = 2; break;
        default: panic("AES A9: Invalid key length");
    }
    switch(op & AES_MODE_MASK)
    {
        case AES_ENCRYPT: encrypt = 1; break;
        case AES_DECRYPT: encrypt = 0; break;
    }
    switch(op & AES_CIPHER_MASK)
    {
        case AES_CBC: mode = 1; break;
        case AES_ECB: mode = 0; break;
    }
    uint32_t keysel = (mode << 13) | (encrypt << 12) | (bits << 6) | (keyid << 4);

    clock_gate(gAESClockAddr, 1);

    // Set key
    if((op & AES_KEY_MASK) == AES_USER_KEY)
    {
        rAES_KEY_WORD(0) = u32_key[0];
        rAES_KEY_WORD(1) = u32_key[1];
        rAES_KEY_WORD(2) = u32_key[2];
        rAES_KEY_WORD(3) = u32_key[3];
        if(bits > 0)
        {
            rAES_KEY_WORD(4) = u32_key[4];
            rAES_KEY_WORD(5) = u32_key[5];
            if(bits > 1)
            {
                rAES_KEY_WORD(6) = u32_key[6];
                rAES_KEY_WORD(7) = u32_key[7];
            }
        }
    }
    rAES_KEY_CTL = keysel | 1;

    // Set IV
    if(u32_iv)
    {
        rAES_IV_WORD(0) = u32_iv[0];
        rAES_IV_WORD(1) = u32_iv[1];
        rAES_IV_WORD(2) = u32_iv[2];
        rAES_IV_WORD(3) = u32_iv[3];
    }
    else
    {
        rAES_IV_WORD(0) = 0;
        rAES_IV_WORD(1) = 0;
        rAES_IV_WORD(2) = 0;
        rAES_IV_WORD(3) = 0;
    }
    rAES_IV_CTL = 1;

    // AES block loop
    for(size_t off = 0; off < len; off += 0x10)
    {
        // Wait for ready
        while((rAES_IN_STS & 0x1) != 0x1) {}

        // Load input
        rAES_INPUT(0) = u32_src[0];
        rAES_INPUT(1) = u32_src[1];
        rAES_INPUT(2) = u32_src[2];
        rAES_INPUT(3) = u32_src[3];

        // Clock
        rAES_CTL = 1;

        // Wait for completion
        while((rAES_OUT_STS & 0x1) != 0x1) {}

        // Store output
        u32_dst[0] = rAES_OUTPUT(0);
        u32_dst[1] = rAES_OUTPUT(1);
        u32_dst[2] = rAES_OUTPUT(2);
        u32_dst[3] = rAES_OUTPUT(3);

        u32_src += 4;
        u32_dst += 4;
    }

    clock_gate(gAESClockAddr, 0);

    return 0;
}
