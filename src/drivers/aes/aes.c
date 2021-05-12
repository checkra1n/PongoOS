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
#include <string.h>
#include <pongo.h>

#include "aes.h"
#include "aes_private.h"

static int (*aes_impl)(uint32_t op, const void *src, void *dst, size_t len, const void *iv, const void *key);

void aes_cmd(const char *cmd, char *args)
{
    uint32_t mode  = AES_CBC;
    uint32_t op    = AES_DECRYPT;
    uint32_t bits  = AES_256;
    uint32_t keyid = AES_USER_KEY;
    size_t keylen  = 0x20;
    uint8_t iv[0x10];
    uint8_t key[0x20];
    uint8_t *realiv = NULL,
            *realkey = NULL,
            *data = NULL;
    char *parts[5] = {};

    while(*args == ' ') ++args;
    for(size_t i = 0; i < 5; ++i)
    {
        char *delim = strchr(args, ' ');
        parts[i] = args;
        if(!delim)
        {
            goto skip;
        }
        *delim = '\0';
        args = delim + 1;
        while(*args == ' ') ++args;
    }
    if(*args != '\0')
    {
        iprintf("Too many arguments\n");
        goto help;
    }
skip:;
    if(parts[0][0] == '\0')
    {
        goto help;
    }
    if(!parts[1])
    {
        iprintf("Too few arguments\n");
        goto help;
    }

    size_t idx = 0;
    if(     strcmp(parts[idx], "cbc") == 0) { mode = AES_CBC; ++idx; }
    else if(strcmp(parts[idx], "ecb") == 0) { mode = AES_ECB; ++idx; }

    if(     strcmp(parts[idx], "enc") == 0) { op = AES_ENCRYPT; ++idx; }
    else if(strcmp(parts[idx], "dec") == 0) { op = AES_DECRYPT; ++idx; }

    if(!parts[idx]) { iprintf("Too few arguments\n"); goto help; }
    if(     strcmp(parts[idx], "128") == 0) { bits = AES_128; keylen = 0x10; ++idx; }
    else if(strcmp(parts[idx], "192") == 0) { bits = AES_192; keylen = 0x18; ++idx; }
    else if(strcmp(parts[idx], "256") == 0) { bits = AES_256; keylen = 0x20; ++idx; }

    if(!parts[idx+1]) { iprintf("Too few arguments\n"); goto help; }
    if(     strcmp(parts[idx], "uid")  == 0) { keyid = AES_UID;  }
    else if(strcmp(parts[idx], "gid0") == 0) { keyid = AES_GID0; }
    else if(strcmp(parts[idx], "gid1") == 0) { keyid = AES_GID1; }
    else
    {
        char *s = parts[idx];
        if(strlen(s) != 2*(0x10 + keylen) || hexparse(iv, s, 0x10) != 0 || hexparse(key, s + 0x10, keylen) != 0)
        {
            iprintf("Bad key\n");
            goto help;
        }
        realiv = iv;
        realkey = key;
    }
    ++idx;

    size_t sz = strlen(parts[idx]);
    if(!sz)
    {
        iprintf("No data given\n");
        goto help;
    }
    if((sz % 0x20) != 0) // 0x20 because hex
    {
        iprintf("Data must be multiple of AES block size (is 0x%lx)\n", sz);
        goto help;
    }
    sz /= 2;
    data = alloc_contig(sz);
    if(!data)
    {
        panic("AES cmd: malloc failed (%lu)\n", sz);
    }
    if(hexparse(data, parts[idx], sz) != 0)
    {
        iprintf("Bad data\n");
        goto help;
    }
    int r = aes(op | mode | bits | keyid, data, data, sz, realiv, realkey);
    if(r != 0)
    {
        iprintf("AES failed: %d\n", r);
    }
    else
    {
        hexprint(data, sz);
    }
    free_contig(data, sz);
    return;
help:;
    if(data) free(data);
    iprintf("Usage: aes [cbc|ecb] [enc|dec] [128|192|256] uid|gid0|gid1|ivkey data\n");
    iprintf("Default is: cbc dec 256\n");
}

void aes_init(void)
{
    switch(socnum)
    {
        case 0x8960:
        case 0x7000:
        case 0x7001:
            aes_a7_init();
            aes_impl = &aes_a7;
            break;
        case 0x8000:
        case 0x8001:
        case 0x8003:
        case 0x8010:
        case 0x8011:
        case 0x8012:
        case 0x8015:
            aes_a9_init();
            aes_impl = &aes_a9;
            break;
        default:
            panic("AES: Unsupported SoC");
    }
    command_register("aes", "performs AES operations", aes_cmd);
}

int aes(uint32_t op, const void *src, void *dst, size_t len, const void *iv, const void *key)
{
    if((op & ~AES_ALL_MASK) != 0)
    {
        return EINVAL;
    }
    switch(op & AES_BITS_MASK)
    {
        case AES_128:
        case AES_192:
        case AES_256:
            break;
        default:
            return EINVAL;
    }
    if((op & AES_KEY_MASK) == AES_USER_KEY && (!iv || !key))
    {
        return EINVAL;
    }
    if(!src || !dst || (len % 0x10) != 0)
    {
        return EINVAL;
    }
    return aes_impl(op, src, dst, len, iv, key);
}
