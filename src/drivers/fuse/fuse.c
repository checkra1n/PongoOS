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

#include <pongo.h>

#include "fuse.h"
#include "fuse_private.h"

static uint64_t gFuseBase;

#define FUSE_REG(n) ((volatile uint32_t*)gFuseBase)[(n)]

bool fuse_is_demoted(void)
{
    return (FUSE_REG(0) & 0x1) == 0x0;
}

bool fuse_is_locked(void)
{
    return (FUSE_REG(1) & 0x80000000) != 0x0;
}

bool fuse_demote(void)
{
    if(fuse_is_demoted())
        return true;

    if(fuse_is_locked())
        return false;

    FUSE_REG(0) &= 0xfffffffe;
    return true;
}

void fuse_lock(void)
{
    FUSE_REG(1) |= 0x80000000;
}

struct fuse_command
{
    const char* name;
    const char* desc;
    void (*cb)(const char *cmd, char *args);
};

static void fuse_cmd_help(const char *cmd, char *args);
static void fuse_cmd_status(const char *cmd, char *args);
static void fuse_cmd_demote(const char *cmd, char *args);
static void fuse_cmd_lock(const char *cmd, char *args);

static const struct fuse_command command_table[] =
{
    {"help",   "show usage", fuse_cmd_help},
    {"status", "print fuse status", fuse_cmd_status},
    {"demote", "demote AP security fuse", fuse_cmd_demote},
    {"lock",   "lock fuse array", fuse_cmd_lock},
};

static void fuse_cmd_help(const char *cmd, char *args)
{
    iprintf("fuse usage: fuse [subcommand]\nsubcommands:\n");
    for(size_t i = 0; i < sizeof(command_table) / sizeof(command_table[0]); ++i)
    {
        iprintf("%8s | %s\n", command_table[i].name, command_table[i].desc);
    }
}

static void fuse_cmd_status(const char *cmd, char *args)
{
    uint32_t val0 = FUSE_REG(0),
             val1 = FUSE_REG(1);
    iprintf("Reg 0: 0x%08x (demoted: %s)\n"
            "Reg 1: 0x%08x (locked: %s)\n",
            val0, (val0 & 0x1) == 0x0 ? "yes" : "no",
            val1, (val1 & 0x80000000) ? "yes" : "no");
}

static void fuse_cmd_demote(const char *cmd, char *args)
{
    if(fuse_is_demoted())
    {
        iprintf("Device is already demoted.\n");
        return;
    }
    if(fuse_is_locked())
    {
        iprintf("Sorry, fuses are already locked.\n");
        return;
    }
    fuse_demote();
}

static void fuse_cmd_lock(const char *cmd, char *args)
{
    if(fuse_is_locked())
    {
        iprintf("Fuses are already locked.\n");
        return;
    }
    fuse_lock();
}

static void fuse_cmd(const char* cmd, char *args)
{
    char *arguments = command_tokenize(args, 0x1ff - (args - cmd));
    if(arguments)
    {
        for(size_t i = 0; i < sizeof(command_table) / sizeof(command_table[0]); ++i)
        {
            if(strcmp(args, command_table[i].name) == 0)
            {
                command_table[i].cb(args, arguments);
                return;
            }
        }
        if(args[0] != '\0')
        {
            iprintf("fuse: invalid command %s\n", args);
        }
        fuse_cmd_help(cmd, arguments);
    }
}

void fuse_init(void)
{
    switch(socnum)
    {
        case 0x8960:
        case 0x7000:
        case 0x7001:
            gFuseBase = 0x20e02a000;
            break;

        case 0x8000:
        case 0x8003:
        case 0x8001:
        case 0x8010:
        case 0x8011:
            gFuseBase = 0x2102bc000;
            break;

        case 0x8012:
            gFuseBase = 0x2112bc000;
            break;

        case 0x8015:
            gFuseBase = 0x2352bc000;
            break;

        default:
            panic("Fuse: Unsupported SoC");
    }

    command_register("fuse", "fuse array access", fuse_cmd);
}
