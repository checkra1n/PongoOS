/*
 * pongoOS - https://checkra.in
 *
 * Copyright (C) 2019-2023 checkra1n team
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

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pongo.h"
#include "tz.h"

static bool gHaveTZ1 = false;
static volatile uint32_t *gTZRegbase[2];

static bool tz_idx_shift(uint8_t which, uint8_t *idx, uint8_t *shift)
{
    if(shift) *shift = socnum == 0x8960 ? 20 : 12;
    switch(which)
    {
        case 0:
            if(idx) *idx = socnum == 0x8960 ? 2 : 0;
            return true;

        case 1:
            if(!gHaveTZ1)
            {
                return false;
            }
            if(idx) *idx = socnum == 0x8960 ? 3 : 2;
            return true;

        default:
            return false;
    }
}

static bool tz_get_raw(uint8_t which, uint8_t slot, uint8_t *shift, uint32_t *start, uint32_t *end)
{
    uint8_t idx;
    if(!tz_idx_shift(which, &idx, shift))
    {
        return false;
    }

    volatile uint32_t *reg = gTZRegbase[slot];
    if(!reg)
    {
        return false;
    }
    if(socnum == 0x8960)
    {
        uint32_t val = reg[idx];
        *start = val & 0xffff;
        *end = (val >> 16) & 0xffff;
    }
    else
    {
        *start = reg[idx];
        *end = reg[idx+1];
    }
    return true;
}

bool tz_get(uint8_t which, uint64_t *base, uint64_t *size)
{
    uint8_t shift;
    uint32_t start, end;
    if(!tz_get_raw(which, 0, &shift, &start, &end))
    {
        return false;
    }
    if(base) *base = ((uint64_t)start << shift) + 0x800000000ULL;
    if(size) *size = ((uint64_t)(end - start + 1) << shift);
    return true;
}

static bool tz_set_raw(uint8_t which, uint32_t start, uint32_t end)
{
    uint8_t idx;
    if(!tz_idx_shift(which, &idx, NULL))
    {
        return false;
    }

    for(uint8_t i = 0; i < sizeof(gTZRegbase)/sizeof(*gTZRegbase); ++i)
    {
        volatile uint32_t *reg = gTZRegbase[i];
        if(!reg)
        {
            continue;
        }
        if(socnum == 0x8960)
        {
            reg[idx] = (start & 0xffff) | ((end & 0xffff) << 16);
        }
        else
        {
            reg[idx] = start;
            reg[idx+1] = end;
        }
        __asm__ volatile("dmb sy");
    }
    return true;
}

bool tz_set(uint8_t which, uint64_t base, uint64_t size)
{
    uint8_t shift;
    if(!tz_idx_shift(which, NULL, &shift))
    {
        return false;
    }

    uint32_t start = base >> shift;
    uint32_t end = (base + size - 1) >> shift;
    return tz_set_raw(which, start, end);
}

bool tz_locked(uint8_t which)
{
    switch(which)
    {
        case 0:
            break;

        case 1:
            if(!gHaveTZ1)
            {
                return false;
            }
            break;

        default:
            return false;
    }

    bool locked = true;
    for(uint8_t i = 0; i < sizeof(gTZRegbase)/sizeof(*gTZRegbase); ++i)
    {
        volatile uint32_t *reg = gTZRegbase[i];
        if(!reg)
        {
            continue;
        }
        if((reg[4 + which] & 1) == 0)
        {
            locked = false;
        }
    }
    return locked;
}

bool tz_lock(uint8_t which)
{
    switch(which)
    {
        case 0:
            break;

        case 1:
            if(!gHaveTZ1)
            {
                return false;
            }
            break;

        default:
            return false;
    }

    bool locked = true;
    for(uint8_t i = 0; i < sizeof(gTZRegbase)/sizeof(*gTZRegbase); ++i)
    {
        volatile uint32_t *reg = gTZRegbase[i];
        if(!reg)
        {
            continue;
        }
        reg[4 + which] = 1;
        __asm__ volatile("dmb sy");
        if((reg[4 + which] & 1) == 0)
        {
            locked = false;
        }
    }
    return locked;
}

bool tz_lockdown(void)
{
    bool lock0 = tz_lock(0);
    bool lock1 = gHaveTZ1 ? tz_lock(1) : true;
    return lock0 && lock1;
}

bool tz_blackbird(void)
{
    if(socnum == 0x8960 || tz_locked(0))
    {
        return false;
    }
    for(uint8_t i = 0; i < sizeof(gTZRegbase)/sizeof(*gTZRegbase); ++i)
    {
        volatile uint32_t *reg = gTZRegbase[i];
        if(!reg)
        {
            continue;
        }
        if((reg[4] & 1) != 0)
        {
            return false;
        }
        reg[0] |= 0x100000;
        __asm__ volatile("dmb sy");
    }
    return true;
}

uint64_t tz0_calculate_encrypted_block_offset(uint64_t offset)
{
    switch(socnum)
    {
        case 0x8960:
            return offset & ~0xfULL;

        case 0x8015:
            return (offset & ~0x3fULL) << 1;

        default:
            return (offset & ~0x1fULL) << 1;
    }
}

struct tz_command
{
    const char* name;
    const char* desc;
    void (*cb)(const char *cmd, char *args);
};

static void tz_cmd_help(const char *cmd, char *args);
static void tz_cmd_status(const char *cmd, char *args);
static void tz_cmd_lock(const char *cmd, char *args);
static void tz_cmd_set(const char *cmd, char *args);
static void tz_cmd_blackbird(const char *cmd, char *args);

static const struct tz_command command_table[] =
{
    {"help", "show usage", tz_cmd_help},
    {"status", "print trustzone registers", tz_cmd_status},
    {"lock", "lock trustzone registers", tz_cmd_lock},
    {"set",  "set trustzone registers to custom values", tz_cmd_set},
    {"blackbird", "trustzone blackbird attack", tz_cmd_blackbird},
};

static void tz_cmd_help(const char *cmd, char *args)
{
    iprintf("tz usage: tz [subcommand]\nsubcommands:\n");
    for(size_t i = 0; i < sizeof(command_table) / sizeof(command_table[0]); ++i)
    {
        iprintf("%12s | %s\n", command_table[i].name, command_table[i].desc);
    }
}

static void tz_cmd_status(const char *cmd, char *args)
{
    for(uint8_t i = 0; i < sizeof(gTZRegbase)/sizeof(*gTZRegbase); ++i)
    {
        for(uint8_t which = 0; which <= 1; ++which)
        {
            uint8_t shift;
            uint32_t start, end;
            if(tz_get_raw(which, i, &shift, &start, &end))
            {
                uint64_t base = ((uint64_t)start     << shift) + 0x800000000ULL;
                uint64_t top  = ((uint64_t)(end + 1) << shift) + 0x800000000ULL;
                iprintf("TZ%hhu (%s):\n"
                        "    base: 0x%x (0x%llx)\n"
                        "    end:  0x%x (0x%llx)\n"
                        "\n",
                        which, (gTZRegbase[i][4 + which] & 1) != 0 ? "locked" : "unlocked",
                        start, base, end, top);
            }
        }
    }
}

static void tz_cmd_lock(const char *cmd, char *args)
{
    bool lock0 = false,
         lock1 = false;
    if(args[0] == '\0')
    {
        lock0 = true;
        lock1 = gHaveTZ1;
    }
    else if(strcmp(args, "0") == 0)
    {
        lock0 = true;
    }
    else if(strcmp(args, "1") == 0)
    {
        lock1 = true;
    }
    else
    {
        iprintf("Bad argument: %s\n", args);
        return;
    }

    if(lock0)
    {
        if(tz_locked(0))
        {
            iprintf("TZ0 already locked.\n");
        }
        else if(!tz_lock(0))
        {
            iprintf("Failed to lock TZ0.\n");
        }
    }
    if(lock1)
    {
        if(tz_locked(1))
        {
            iprintf("TZ1 already locked.\n");
        }
        else if(!tz_lock(1))
        {
            iprintf("Failed to lock TZ1.\n");
        }
    }
}

static void tz_cmd_set(const char *cmd, char *args)
{
    char *zone = command_tokenize(args, 0x1ff - (args - cmd));
    if(zone && *zone)
    {
        char *base = command_tokenize(zone, 0x1ff - (zone - cmd));
        if(base && *base)
        {
            char *size = command_tokenize(base, 0x1ff - (base - cmd));
            if(size && *size)
            {
                uint8_t zone_arg = strcmp(zone, "0") == 0 ? 0
                                 : strcmp(zone, "1") == 0 ? 1
                                 : -1;
                char *base_end = NULL;
                char *size_end = NULL;
                unsigned long long base_arg = strtoull(base, &base_end, 0);
                unsigned long long size_arg = strtoull(size, &size_end, 0);
                if(zone_arg != 0 && zone_arg != 1) iprintf("Bad zone argument: %s\n", zone);
                if(*base_end) iprintf("Bad base argument: %s\n", base);
                if(*size_end) iprintf("Bad size argument: %s\n", size);
                if((zone_arg == 0 || zone_arg == 1) && !*base_end && !*size_end)
                {
                    if(!tz_set(zone_arg, base_arg, size_arg))
                    {
                        iprintf("Failed to set TZ values.\n");
                    }
                    return;
                }
            }
        }
    }
    iprintf("tz set usage: tz set [zone] [base] [size]\n");
}

static void tz_cmd_set_legacy(const char *cmd, char *args)
{
    char *reg0 = command_tokenize(args, 0x1ff - (args - cmd));
    if(reg0 && *reg0)
    {
        char *reg1 = command_tokenize(reg0, 0x1ff - (reg0 - cmd));
        if(reg1 && *reg1)
        {
            char *reg0_end = NULL;
            char *reg1_end = NULL;
            unsigned long long reg0_arg = strtoull(reg0, &reg0_end, 0);
            unsigned long long reg1_arg = strtoull(reg1, &reg1_end, 0);
            if(*reg0_end) iprintf("Bad reg0 argument: %s\n", reg0);
            if(*reg1_end) iprintf("Bad reg1 argument: %s\n", reg1);
            if(!*reg0_end || !*reg1_end)
            {
                if(!tz_set_raw(0, (uint32_t)reg0_arg, (uint32_t)reg1_arg))
                {
                    iprintf("Failed to set TZ0 values.\n");
                }
                return;
            }
        }
    }
    iprintf("tz0_set usage: tz0_set [reg0] [reg1]\n");
}

static void tz_cmd_blackbird(const char *cmd, char *args)
{
    if(socnum == 0x8960)
    {
        iprintf("Not supported on this SoC.\n");
        return;
    }
    if(tz_locked(0))
    {
        iprintf("TZ0 is already locked.\n");
        return;
    }
    if(!tz_blackbird())
    {
        iprintf("Failed to perform blackbird.\n");
    }
}

static void tz_cmd(const char* cmd, char *args)
{
    char *arguments = command_tokenize(args, 0x1ff - (args - cmd));
    if(arguments)
    {
        for(size_t i = 0; i < sizeof(command_table) / sizeof(command_table[0]); ++i)
        {
            if(strcmp(args, command_table[i].name) == 0)
            {
                command_table[i].cb(cmd, arguments);
                return;
            }
        }
        if(args[0] != '\0')
        {
            iprintf("tz: invalid command %s\n", args);
        }
        tz_cmd_help(cmd, arguments);
    }
}

void tz_setup(void)
{
    switch(socnum)
    {
        case 0x8960:
            gHaveTZ1 = true;
            gTZRegbase[0] = (volatile uint32_t*)(gIOBase + 0x900);
            break;

        case 0x8001:
            gTZRegbase[1] = (volatile uint32_t*)(gIOBase + 0x200480);
            /* fallthrough */

        case 0x7000:
        case 0x7001:
        case 0x8000:
        case 0x8003:
            gHaveTZ1 = true;
            /* fallthrough */

        case 0x8010:
        case 0x8011:
        case 0x8012:
        case 0x8015:
            gTZRegbase[0] = (volatile uint32_t*)(gIOBase + 0x480);
            break;

        default:
            panic("Unsupported SoC");
    }

    command_register("tz", "trustzone management", tz_cmd);
    // Keep these for legacy compat, but hide them from help
    _command_register_internal("tz0_set",      NULL, tz_cmd_set_legacy, true);
    _command_register_internal("tz_lockdown",  NULL, tz_cmd_lock, true);
    _command_register_internal("tz_blackbird", NULL, tz_cmd_blackbird, true);
}
