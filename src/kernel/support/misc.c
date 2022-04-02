/*
 * pongoOS - https://checkra.in
 *
 * Copyright (C) 2019-2022 checkra1n team
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
#include <sys/errno.h>

// TODO: transfer those to the right place
void __muldc3() { panic("__muldc3"); }
void __mulsc3() { panic("__mulsc3"); }
void __muloti4() { panic("__muloti4"); }
wint_t _jp2uc_l (wint_t c, struct __locale_t *l) { return c; }
wint_t _uc2jp_l (wint_t c, struct __locale_t *l) { return c; }
int regcomp() { panic("regcomp"); }
int regexec() { panic("regexec"); }
int regfree() { panic("regfree"); }
int getentropy()    { errno = ENOSYS; return -1; }
int _gettimeofday() { errno = ENOSYS; return -1; }
int _times()        { errno = ENOSYS; return -1; }
int _fcntl()        { errno = ENOSYS; return -1; }
int _stat()         { errno = ENOSYS; return -1; }
int _link()         { errno = ENOSYS; return -1; }
int _unlink()       { errno = ENOSYS; return -1; }
int _mkdir()        { errno = ENOSYS; return -1; }
int _fork()         { errno = ENOSYS; return -1; }
int _execve()       { errno = ENOSYS; return -1; }
int _wait()         { errno = ENOSYS; return -1; }
int sigprocmask()   { errno = ENOSYS; return -1; }
