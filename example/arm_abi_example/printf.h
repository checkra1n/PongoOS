/* 
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
 *  Copyright fugiefire 2020
 *  This file is part of pongoOS.
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