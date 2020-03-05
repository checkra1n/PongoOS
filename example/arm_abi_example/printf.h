/*
 *  printf.h
 *  Copyright fugiefire 2020
 *  You are free to redistribute/modify this code under the 
 *  terms of the GPL version 3 (see the file LICENSE)
 */

#ifndef __GNUC_VA_LIST
#define __GNUC_VA_LIST
typedef __builtin_va_list __gnuc_va_list;
#endif /* __GNUC_VA_LIST */

#ifndef __va_list__
typedef __gnuc_va_list va_list;
#endif /* __va_list__ */

#ifndef __va_funcs__
#define __va_funcs__
#ifndef va_start
#define va_start(v, l) __builtin_va_start(v, l)
#endif // va_start
#ifndef va_end
#define va_end(v) __builtin_va_end(v)
#endif // va_end
#ifndef va_arg
#define va_arg(v, l) __builtin_va_arg(v, l)
#endif // va_arg
#endif /* __va_funcs__ */

void arm_abi_example_vsprintf(char *str, void (*putchar)(char), const char *fmt, va_list ap);
void arm_abi_example_printf(const char *str, ...);