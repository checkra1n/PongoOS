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
#include <stdlib.h>
#include <pongo.h>
struct task* command_task;
char command_buffer[0x200];
int command_buffer_idx = 0;

struct command {
    const char* name;
    const char* desc;
    void (*cb)(const char* cmd, char* args);
} commands[64];
char is_masking_autoboot;
static lock command_lock;

static int cmp_cmd(const void *a, const void *b)
{
    const struct command *x = a, *y = b;
    if(!x->name && !y->name) return 0;
    if(!x->name) return 1;
    if(!y->name) return -1;
    return strcmp(x->name, y->name);
}

void command_unregister(const char* name) {
    lock_take(&command_lock);
    for (int i=0; i<64; i++) {
        if (commands[i].name && strcmp(commands[i].name, name) == 0) {
            commands[i].name = 0;
            commands[i].desc = 0;
            commands[i].cb = 0;
        }
    }
    qsort(commands, 64, sizeof(struct command), &cmp_cmd);
    lock_release(&command_lock);
}
void command_register(const char* name, const char* desc, void (*cb)(const char* cmd, char* args)) {
    if (is_masking_autoboot && strcmp(name,"autoboot") == 0) return;
    lock_take(&command_lock);
    for (int i=0; i<64; i++) {
        if (!commands[i].name || strcmp(commands[i].name, name) == 0) {
            commands[i].name = name;
            commands[i].desc = desc;
            commands[i].cb = cb;
            qsort(commands, 64, sizeof(struct command), &cmp_cmd);
            lock_release(&command_lock);
            return;
        }
    }
    lock_release(&command_lock);
    panic("too many commands");
}

char* command_tokenize(char* str, uint32_t strbufsz) {
    char* bound = &str[strbufsz];
    while (*str) {
        if (str > bound) return NULL;
        if (*str == ' ') {
            *str++ = 0;
            while (*str) {
                if (str > bound) return NULL;
                if (*str == ' ') {
                    str++;
                } else
                    break;
            }
            if (str > bound) return NULL;
            if (!*str) return "";
            return str;
        }
        str++;
    }
    return "";
}

char is_executing_command;
uint32_t command_flags;
#define COMMAND_NOTFOUND 1
void command_execute(char* cmd) {
    char* arguments = command_tokenize(cmd, 0x1ff);
    if (arguments) {
        lock_take(&command_lock);
        for (int i=0; i<64; i++) {
            if (commands[i].name && !strcmp(cmd, commands[i].name)) {
                void (*cb)(const char* cmd, char* args) = commands[i].cb;
                lock_release(&command_lock);
                cb(command_buffer, arguments);
                return;
            }
        }
        lock_release(&command_lock);
    }
    if(cmd[0] != '\0')
    {
        iprintf("Bad command: %s\n", cmd);
    }
    if (*cmd)
        command_flags |= COMMAND_NOTFOUND;
}

extern uint32_t uart_should_drop_rx;
char command_handler_ready = 0;
volatile uint8_t command_in_progress = 0;
struct event command_handler_iter;

static inline void put_serial_modifier(const char* str) {
    while (*str) serial_putc(*str++);
}

void command_main() {
    while (1) {
        if (!uart_should_drop_rx) {
            fflush(stdout);
            putchar('\r');
            if (command_flags & COMMAND_NOTFOUND) {
                put_serial_modifier("\x1b[31m");
            }
            iprintf("pongoOS> ");
            fflush(stdout);
            if (command_flags & COMMAND_NOTFOUND) {
                put_serial_modifier("\x1b[0m");
                command_flags &= ~COMMAND_NOTFOUND;
            }
        }
        fflush(stdout);
        event_fire(&command_handler_iter);
        command_handler_ready = 1;
        command_in_progress = 0;
        fgets(command_buffer,512,stdin);
        command_in_progress = 1;
        char* cmd_end = command_buffer + strlen(command_buffer);
        while (cmd_end != command_buffer) {
            cmd_end --;
            if (cmd_end[0] == '\n' || cmd_end[0] == '\r')
                cmd_end[0] = 0;
        }
        command_execute(command_buffer);
    }
}

void help(const char * cmd, char* arg) {
    lock_take(&command_lock);
    for (int i=0; i<64; i++) {
        if (commands[i].name) {
            iprintf("%16s | %s\n", commands[i].name, commands[i].desc ? commands[i].desc : "no description");
        }
    }
    lock_release(&command_lock);
}
void command_init() {
    command_task = task_create("command", command_main);
    command_task->flags |= TASK_RESTART_ON_EXIT;
    command_task->flags &= ~TASK_CAN_EXIT;
    command_register("help", "shows this help message", help);
}
