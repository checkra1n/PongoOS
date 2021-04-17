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

enum
{
    AES_OP_KEY   = 0x10000000,
    AES_OP_IV    = 0x20000000,
    AES_OP_DATA  = 0x50000000,
    AES_OP_FLAGS = 0x80000000,
};

enum
{
    AES_FLAG_STOP = 0x04000000,
    AES_FLAG_INT  = 0x08000000,
};

enum
{
    AES_BLOCK_START = 1,
    AES_BLOCK_STOP  = 2,
};

static uintptr_t gAESBase;
static uintptr_t gAESPipeBase;
static uint64_t gAESClockAddr;

#define rAES_CTL    *(volatile uint32_t*)(gAESBase + 0x008)
#define rAES_INT    *(volatile uint32_t*)(gAESBase + 0x018)
#define rAES_PIPE   *(volatile uint32_t*)(gAESPipeBase)

void aes_a9_init(void)
{
    gAESBase = gIOBase + dt_get_u64_prop("aes", "reg");
    gAESPipeBase = gAESBase + 0x200;
    switch(socnum)
    {
        case 0x8000:
        case 0x8003:
            gAESPipeBase  = gAESBase + 0x100;
            gAESClockAddr = gIOBase + 0x0e080220;
            break;
        case 0x8001:
            gAESClockAddr = gIOBase + 0x0e080218;
            break;
        case 0x8010:
            gAESClockAddr = gIOBase + 0x0e080230;
            break;
        case 0x8011:
            gAESClockAddr = gIOBase + 0x0e080228;
            break;
        case 0x8012:
            gAESClockAddr = gIOBase + 0x0e080238;
            break;
        case 0x8015:
            gAESClockAddr = gIOBase + 0x32080240;
            break;
        default:
            panic("AES A9: counterfeit init call");
    }
    // XXX: Why is PMGR hating like that?!
    /*gAESClockAddr = device_clock_addr(dt_get_u32_prop("aes", "clock-gates"));
    if(!gAESClockAddr)
    {
        panic("AES A9: clock base missing from DeviceTree");
    }*/
}

int aes_a9(uint32_t op, const void *src, void *dst, size_t len, const void *iv, const void *key)
{
    uint64_t src_addr = vatophys((uint64_t)src),
             dst_addr = vatophys((uint64_t)dst);
    if((len & ~0xfffff0ULL) || (src_addr & 0xffffff0000000000) || (dst_addr & 0xfffff0000000000))
    {
        return EFAULT;
    }
    const uint32_t *u32_key = key,
                   *u32_iv  = iv;
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
    uint32_t op_key = AES_OP_KEY | (keyid << 24) | (bits << 22) | (encrypt << 20) | (mode << 16);

    clock_gate(gAESClockAddr, 1);

    cache_clean((void*)src, len);
    if(src_addr != dst_addr)
    {
        // Need to commit writes to dest as well
        cache_clean(dst, len);
    }

    // Clear interrupts or smth
    rAES_INT = 0x20;

    // Start block
    rAES_CTL = AES_BLOCK_START;

    // Push key
    rAES_PIPE = op_key;
    if((op & AES_KEY_MASK) == AES_USER_KEY)
    {
        rAES_PIPE = u32_key[0];
        rAES_PIPE = u32_key[1];
        rAES_PIPE = u32_key[2];
        rAES_PIPE = u32_key[3];
        if(bits > 0)
        {
            rAES_PIPE = u32_key[4];
            rAES_PIPE = u32_key[5];
            if(bits > 1)
            {
                rAES_PIPE = u32_key[6];
                rAES_PIPE = u32_key[7];
            }
        }
    }

    // Push IV
    rAES_PIPE = AES_OP_IV;
    if(u32_iv)
    {
        rAES_PIPE = u32_iv[0];
        rAES_PIPE = u32_iv[1];
        rAES_PIPE = u32_iv[2];
        rAES_PIPE = u32_iv[3];
    }
    else
    {
        rAES_PIPE = 0;
        rAES_PIPE = 0;
        rAES_PIPE = 0;
        rAES_PIPE = 0;
    }

    // Push data
    rAES_PIPE = AES_OP_DATA | (len & 0xfffff0);
    rAES_PIPE = ((src_addr >> 16) & 0xFF0000) | ((dst_addr >> 32) & 0xff);
    rAES_PIPE = (uint32_t)src_addr;
    rAES_PIPE = (uint32_t)dst_addr;

    // Do the thing
    rAES_PIPE = AES_OP_FLAGS | AES_FLAG_STOP | AES_FLAG_INT;

    // Wait for completion
    while((rAES_INT & 0x20) == 0) {}
    rAES_INT = 0x20;

    cache_invalidate(dst, len);

    // End block
    rAES_CTL = AES_BLOCK_STOP;

    clock_gate(gAESClockAddr, 0);

    return 0;
}
