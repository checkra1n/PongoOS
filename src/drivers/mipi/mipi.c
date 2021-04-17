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


static uint64_t gmipi_reg;
void mipi_sleep() {
    if (!gmipi_reg) return;
    mipi_send_cmd(0x2805);
    spin(24 * 1000 * 20); // 20ms delay
    mipi_send_cmd(0x1005);
    spin(24 * 1000 * 20); // 20ms delay
}
void mipi_wake() {
    if (!gmipi_reg) return;
    mipi_send_cmd(0x2905);
    spin(24 * 1000 * 20); // 20ms delay
    mipi_send_cmd(0x1105);
    spin(24 * 1000 * 20); // 20ms delay
}
void mipi_send_cmd(uint32_t cmd) {
    if (!gmipi_reg) panic("mipi is not setup");
    *(volatile uint32_t*)(gmipi_reg + 0x6C) = cmd;
    while (1) {
        if (*(volatile uint32_t*)(gmipi_reg + 0x74) & 1) {
            break;
        }
    }
}

struct mipi_command {
    char* name;
    char* desc;
    void (*cb)(const char* cmd, char* args);
};

#define MIPI_COMMAND(_name, _desc, _cb) {.name = _name, .desc = _desc, .cb = _cb}

void mipi_help(const char* cmd, char* args);
static struct mipi_command command_table[] = {
    MIPI_COMMAND("help", "shows this message", mipi_help),
    MIPI_COMMAND("sleep", "sends sleep command to mipi", mipi_sleep),
    MIPI_COMMAND("wake", "sends wake command to mipi", mipi_wake)
};

void mipi_help(const char* cmd, char* args) {
    iprintf("mipi usage: mipi [subcommand] <subcommand options>\nsubcommands:\n");
    for (int i=0; i < sizeof(command_table) / sizeof(struct mipi_command); i++) {
        if (command_table[i].name) {
            iprintf("%16s | %s\n", command_table[i].name, command_table[i].desc ? command_table[i].desc : "no description");
        }
    }
}

void mipi_cmd(const char* cmd, char* args) {
    char* arguments = command_tokenize(args, 0x1ff - (args - cmd));
    struct mipi_command* fallback_cmd = NULL;
    if (arguments) {
        for (int i=0; i < sizeof(command_table) / sizeof(struct mipi_command); i++) {
            if (command_table[i].name && !strcmp("help", command_table[i].name)) {
                fallback_cmd = &command_table[i];
            }
            if (command_table[i].name && !strcmp(args, command_table[i].name)) {
                command_table[i].cb(args, arguments);
                return;
            }
        }
        if (*args)
            iprintf("mipi: invalid command %s\n", args);
        if (fallback_cmd) return fallback_cmd->cb(cmd, arguments);
    }
}

void mipi_init() {
    if(dt_find(gDeviceTree, "mipi-dsim")) {
        uint64_t mipi_reg = dt_get_u32_prop("mipi-dsim", "reg");
        mipi_reg += gIOBase;
        gmipi_reg = mipi_reg;
        command_register("mipi", "mipi tools", mipi_cmd);
    }
}

