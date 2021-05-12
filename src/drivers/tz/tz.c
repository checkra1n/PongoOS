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
#import <pongo.h>

volatile uint32_t *gTZRegbase;

static void tz_command(const char* cmd, char* args) {
    uint32_t raw[4];
    uint32_t shift;
    if(socnum == 0x8960)
    {
        uint32_t one = gTZRegbase[2];
        uint32_t two = gTZRegbase[3];
        raw[0] = one & 0xffff;
        raw[1] = (one >> 16) & 0xffff;
        raw[2] = two & 0xffff;
        raw[3] = (two >> 16) & 0xffff;
        shift = 20;
    }
    else
    {
        raw[0] = gTZRegbase[0];
        raw[1] = gTZRegbase[1];
        raw[2] = gTZRegbase[2];
        raw[3] = gTZRegbase[3];
        shift = 12;
    }
    uint64_t real[4];
    real[0] = ( (uint64_t)raw[0]      << shift) + 0x800000000ULL;
    real[1] = (((uint64_t)raw[1] + 1) << shift) + 0x800000000ULL;
    real[2] = ( (uint64_t)raw[2]      << shift) + 0x800000000ULL;
    real[3] = (((uint64_t)raw[3] + 1) << shift) + 0x800000000ULL;
    iprintf("TZ0 (%s):\n"
            "    base: %x (%llx)\n"
            "    end:  %x (%llx)\n"
            "\n"
            "TZ1 (%s):\n"
            "    base: %x (%llx)\n"
            "    end:  %x (%llx)\n"
            "\n",
            gTZRegbase[4] ? "locked" : "unlocked",
            raw[0], real[0],
            raw[1], real[1],
            gTZRegbase[5] ? "locked" : "unlocked",
            raw[2], real[2],
            raw[3], real[3]);
}

void tz_lockdown(void) {
    bool have_tz0, have_tz1;
    if(socnum == 0x8960)
    {
        have_tz0 = (gTZRegbase[2] & 0xffff) != 0;
        have_tz1 = (gTZRegbase[3] & 0xffff) != 0;
    }
    else
    {
        have_tz0 = gTZRegbase[0] != 0;
        have_tz1 = gTZRegbase[2] != 0;
    }
    if(have_tz0) gTZRegbase[4] = 1;
    if(have_tz1) gTZRegbase[5] = 1;
}

bool tz_blackbird(void) {
    if(socnum == 0x8960)
    {
        iprintf("Not supported on this SoC\n");
        return false;
    }
    if(gTZRegbase[4])
    {
        iprintf("Registers are locked\n");
        return false;
    }
    // XXX: This used to be XOR, but that doesn't work well with the expectations in sep.c.
    // This was probably here to allow toggling from the shell, but that could be done via tz0_set.
    gTZRegbase[0] |= 0x100000;
    return true;
}

static void tz0_set(const char* cmd, char* args) {
    // TODO: would be nice to have this exported for code too, but modifying
    // the actual TZ0 range in a XNU-compatible way would be a pain...
    if (! *args) {
        iprintf("tz_set usage: tz0_set [base] [end]\n");
        return;
    }
    char* arg1 = command_tokenize(args, 0x1ff - (args - cmd));
    if (!*arg1) {
        iprintf("tz_set usage: tz0_set [base] [end]\n");
        return;
    }
    uint64_t base = strtoull(args, NULL, 16);
    uint64_t end = strtoull(arg1, NULL, 16);
    if (gTZRegbase[4]) {
        iprintf("registers are locked\n");
        return;
    }
    if(socnum == 0x8960)
    {
        gTZRegbase[2] = (base & 0xffff) | ((end & 0xffff) << 16);
    }
    else
    {
        gTZRegbase[0] = base;
        gTZRegbase[1] = end;
    }
}

void *tz0_calculate_encrypted_block_addr(uint64_t offset) {
    uint64_t offset_block = (offset & (~0x1f));
    offset_block <<= 1; // * 2
    // TODO: get rid of this magic constant
    // Maybe change the API to just return an offset and let the caller add it to their memory base?
    return (void*)(0xc00000000ULL + offset_block);
}

bool tz0_is_locked(void)
{
    return gTZRegbase[4] != 0;
}

uint64_t tz0_base(void)
{
    if(socnum == 0x8960)
    {
        return ((uint64_t)(gTZRegbase[2] & 0xffff) << 20) + 0x800000000ULL;
    }
    else
    {
        return ((uint64_t)gTZRegbase[0] << 12) + 0x800000000ULL;
    }
}

uint64_t tz0_size(void)
{
    if(socnum == 0x8960)
    {
        uint32_t reg = gTZRegbase[2];
        return (uint64_t)(((reg >> 16) & 0xffff) - (reg & 0xffff) + 1) << 20;
    }
    else
    {
        return (uint64_t)(gTZRegbase[1] - gTZRegbase[0] + 1) << 12;
    }
}

void tz_setup(void) {
    if(socnum == 0x8960)
    {
        gTZRegbase = (volatile uint32_t*)(gIOBase + 0x900);
    }
    else
    {
        gTZRegbase = (volatile uint32_t*)(gIOBase + 0x480);
    }
    // TODO: would be nicer to have everything under just a "tz" command, similar to how "sep" and "recfg" work.
    command_register("tz", "trustzone info", tz_command);
    command_register("tz0_set", "change tz0 registers", (void*)tz0_set);
    command_register("tz_lockdown", "trustzone lockdown", (void*)tz_lockdown);
    command_register("tz_blackbird", "trustzone blackbird attack", (void*)tz_blackbird);
}
