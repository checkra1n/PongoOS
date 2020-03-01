// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
// 
//
//  Copyright (c) 2019-2020 checkra1n team
//  This file is part of pongoOS.
//
#define LL_KTRW_INTERNAL 1
#include <pongo.h>
struct task command_task = {.name = "command"};
char command_buffer[0x200];
int command_buffer_idx = 0;
void command_print(const char* c) {
    iprintf("%s", c);
}
void command_puts(const char* c) {
    disable_interrupts();
    puts(c);
    enable_interrupts();
}
void command_putc(char c) {
    disable_interrupts();
    putc(c, stdout);
    enable_interrupts();
}

struct command {
    const char* name;
    const char* desc;
    void (*cb)(const char* cmd, char* args);
} commands[64];
char is_masking_autoboot;
void command_unregister(const char* name) {
    for (int i=0; i<64; i++) {
        if (commands[i].name && strcmp(commands[i].name, name) == 0) {
            commands[i].name = 0;
            commands[i].desc = 0;
            commands[i].cb = 0;
        }
    }
}
void command_register(const char* name, const char* desc, void (*cb)(const char* cmd, char* args)) {
    command_unregister(name);
    if (is_masking_autoboot && strcmp(name,"autoboot") == 0) return;
    for (int i=0; i<64; i++) {
        if (!commands[i].name) {
            commands[i].name = name;
            commands[i].desc = desc;
            commands[i].cb = cb;
            return;
        }
    }
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

void command_execute(char* cmd) {
    char* arguments = command_tokenize(cmd, 0x1ff);
    if (arguments) {
        for (int i=0; i<64; i++) {
            if (commands[i].name && !strcmp(cmd, commands[i].name)) {
                commands[i].cb(command_buffer, arguments);
                break;
            }
        }
    }
}

extern uint32_t uart_should_drop_rx;
char command_handler_ready = 0;
struct event command_handler_iter;
void command_main() {
    while (1) {
        event_fire(&command_handler_iter);
        if (!uart_should_drop_rx)
            iprintf("\rpongoOS> ");
        fflush(stdout);
        command_handler_ready = 1;
        fgets(command_buffer,512,stdin);
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
    disable_interrupts();
    for (int i=0; i<64; i++) {
        if (commands[i].name) {
            iprintf("%16s | %s\n", commands[i].name, commands[i].desc ? commands[i].desc : "no description");
        }
    }
    enable_interrupts();
}
void command_crashed() {
    task_register(&command_task, command_main);
    command_task.flags |= TASK_CAN_CRASH;
}
void command_init() {
    task_register(&command_task, command_main);
    command_task.flags |= TASK_CAN_CRASH;
    command_task.crash_callback = command_crashed;
    command_register("help", "shows this help message", help);
}
