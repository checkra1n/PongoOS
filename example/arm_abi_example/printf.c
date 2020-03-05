/*
 *  printf.c
 *  Copyright fugiefire 2020
 *  You are free to redistribute/modify this code under the 
 *  terms of the GPL version 3 (see the file LICENSE)
 */

#include "printf.h"
#include <pongo.h>

#ifdef vsprintf
#undef vsprintf
#endif

#define LEAD_ZERO 0x1
#define LONG_NUM 0x2
#define HALF_NUM 0x4
#define SIZE_T_NUM 0x8
#define LONG_LONG_NUM 0x10
#define HALF_HALF_NUM 0x20
#define ALT_FLAG 0x40

#ifdef printf
#undef printf
#endif

void pongo_putc(char c){
    char *str = "x";
    str[0] = c;
    puts(str);
}

void memswp(const char *m1, const char *m2, size_t size) {
    char tmp;
    for (size_t i = 0; i < size; i++) {
        tmp = *((char *)((size_t)m1 + i));
        *((char *)((size_t)m1 + i)) = *((char *)((size_t)m2 + i));
        *((char *)((size_t)m2 + i)) = tmp;
    }
}

void reverse(char *str, size_t len) {
    size_t start = 0;
    size_t end = len - 1;
    while (start < end)
        memswp((char *)((size_t)str + (start++)),
               (char *)((size_t)str + (end--)), 1);
}

void do_itoa(size_t n, char *str, uint8_t base, uint8_t signed_int) {
    if (n == 0) {
        str[0] = '0';
        str[0] = '\0';
        return;
    }

    long long int i, sign;
    if (signed_int)
        if ((sign = n) < 0 && base == 10) n = -n;

    i = 0;
    size_t rem;
    do {
        rem = n % base;
        str[i++] = (rem > 9) ? (rem - 10) + 'a' : rem + '0';
        n /= base;
    } while (n);

    if (signed_int)
        if (sign < 0 && base == 10) str[i++] = '-';
    str[i] = '\0';
    reverse(str, i);
}

void pongo_printf(const char *str, ...){
    va_list(ap);
    va_start(ap, str);
    pongo_vsprintf(NULL, command_putc, str, ap);
    va_end(ap);
}

void pongo_vsprintf(__attribute__((unused)) char *str, void (*putchar)(char),
              const char *fmt, va_list ap) {
    size_t i;
    size_t n;
    char nbuf[32];
    char c;
    unsigned char uc;
    const char *s;
    int flags = 0;
    size_t npad_bytes = 0;
    for (;;) {
        while ((c = *fmt++) != 0) {
            /* Break on format character*/
            if (c == '%') break;
            /* If not a format character, just print it */
            if (c == '\t') {
                /* Treat tabs as 4 spaces */
                putchar(' ');
                putchar(' ');
                putchar(' ');
                putchar(' ');
            } else {
                putchar(c);
            }
        }
        if (c == 0) break;

    next_format_char:
        i = 0;
        /* Ensure that nbuf is zeroed */
        while (i++ < 31) nbuf[i] = 0;
        /* Sanity check that the character after the '%' exists */
        if ((c = *fmt++) == 0) break;
        switch (c) {
            /* %0 - %9 are treated as amount of padding 0's */
            case '0':
                /* Enable leading zero padding */
                flags |= LEAD_ZERO;
                goto next_format_char;
            case '1':
                /* fall through */
            case '2':
                /* fall through */
            case '3':
                /* fall through */
            case '4':
                /* fall through */
            case '5':
                /* fall through */
            case '6':
                /* fall through */
            case '7':
                /* fall through */
            case '8':
                /* fall through */
            case '9':
                /*
                    If a 0 came before this, this number is how many 0's to pad
                    if no 0 came before, this number is how many ' 's to pad
                */
                npad_bytes = (c - '0');
                goto next_format_char;
            case '*':
                /* Treat the next va arg as the amount of padding bytes */
                npad_bytes = va_arg(ap, int);
                goto next_format_char;
            case '.':
                /* Not implemented properly yet */
                goto next_format_char;
            case '%':
                /* "%%", print a physical "%" */
                putchar(c);
                break;
            case '#':
                /* Enable ALT_FLAG, for hex this adds the 0x prefix,
                    for octal 0 prefix, etc. */
                flags |= ALT_FLAG;
                goto next_format_char;
            case 'c':
                /* Print a single character */
                uc = (unsigned char)va_arg(ap, int);
                putchar(uc);
                break;
            case 's':
                /* Print a null terminated string */
                s = va_arg(ap, const char *);
                /* Avoid printing from null */
                if (s == 0) s = "<null>";
                for (i = 0; s[i] != 0; i++) putchar(s[i]);
                break;
            case 'l':
                /* Long int modifier, if it was already
                    enabled, long long modifier */
                if (flags & LONG_NUM) flags |= LONG_LONG_NUM;
                flags |= LONG_NUM;
                goto next_format_char;
            case 'h':
                /* Half int modifier, if it was already
                    enabled, half half modifier */
                if (flags & HALF_NUM) flags |= HALF_HALF_NUM;
                flags |= HALF_NUM;
                goto next_format_char;
            case 'z':
                /* size_t modifier */
                flags |= SIZE_T_NUM;
                goto next_format_char;
            case 'i':
                /* fall through */
            case 'd':
                /* Ensure iterator is 0 */
                i = 0;
                /* Check ll before l, before hh, before h,
                     before size_t modifiers, else normal int */
                /* The (size_t)(type) casting prevents compiler warnings */
                n = (flags & LONG_LONG_NUM)
                        ? (size_t)va_arg(ap, long long)
                        : (flags & LONG_NUM)
                              ? (size_t)va_arg(ap, long)
                              : (flags & HALF_HALF_NUM)
                                    ? (size_t)(signed char)va_arg(ap, int)
                                    : (flags & HALF_NUM)
                                          ? (size_t)(short)va_arg(ap, int)
                                          : (flags & SIZE_T_NUM)
                                                ? va_arg(ap, size_t)
                                                : (size_t)va_arg(ap, int);
                /* Convert to string with signing enabled */
                do_itoa(n, (char *)&nbuf, 10, 1);
                /* Handle padding bytes when padding amount
                    is greater than current length */
                if (npad_bytes > strlen((char *)&nbuf)) {
                    /* Only pad so that the string is of length npad_bytes */
                    npad_bytes -= strlen((char *)&nbuf);
                    /* Print leading zeroes if set, else leading spaces */
                    if (flags & LEAD_ZERO)
                        for (; npad_bytes > 0; npad_bytes--) putchar('0');
                    else
                        for (; npad_bytes > 0; npad_bytes--) putchar(' ');
                }
                /* Write out the value using provided char printing handler */
                for (i = 0; nbuf[i] != 0; i++) putchar(nbuf[i]);
                /* Reset flags and npad_bytes */
                flags = 0;
                npad_bytes = 0;
                break;
            case 'u':
                /* same as case 'd' unless otherwise specified */
                i = 0;
                /* Reading vaargs as unsigned values
                    causes casts to zero extend */
                n = (flags & LONG_LONG_NUM)
                        ? (size_t)va_arg(ap, unsigned long long)
                        : (flags & LONG_NUM)
                              ? (size_t)va_arg(ap, unsigned long)
                              : (flags & HALF_HALF_NUM)
                                    ? (size_t)(signed char)va_arg(ap,
                                                                  unsigned int)
                                    : (flags & HALF_NUM)
                                          ? (size_t)(short)va_arg(ap,
                                                                  unsigned int)
                                          : (flags & SIZE_T_NUM)
                                                ? va_arg(ap, size_t)
                                                : (size_t)va_arg(ap, int);
                /* Convert to string with signing disabled */
                do_itoa(n, (char *)&nbuf, 10, 0);
                if (npad_bytes > strlen((char *)&nbuf)) {
                    npad_bytes -= strlen((char *)&nbuf);
                    if (flags & LEAD_ZERO)
                        for (; npad_bytes > 0; npad_bytes--) putchar('0');
                    else
                        for (; npad_bytes > 0; npad_bytes--) putchar(' ');
                }
                for (i = 0; nbuf[i] != 0; i++) putchar(nbuf[i]);
                flags = 0;
                npad_bytes = 0;
                break;
            case 'p':
                /* Always have 0x prefix for pointers */
                flags |= LONG_NUM | ALT_FLAG;
                goto hex;
            case 'X':
                /* Not implemented */
                /* fall through */
            hex:
            case 'x':
                /* Same logic as case 'u', unless otherwise specified */
                n = (flags & LONG_LONG_NUM)
                        ? (size_t)va_arg(ap, unsigned long long)
                        : (flags & LONG_NUM)
                              ? (size_t)va_arg(ap, unsigned long)
                              : (flags & HALF_HALF_NUM)
                                    ? (size_t)(signed char)va_arg(ap,
                                                                  unsigned int)
                                    : (flags & HALF_NUM)
                                          ? (size_t)(short)va_arg(ap,
                                                                  unsigned int)
                                          : (flags & SIZE_T_NUM)
                                                ? va_arg(ap, size_t)
                                                : (size_t)va_arg(ap,
                                                                 unsigned int);
                do_itoa(n, (char *)&nbuf, 16, 0);
                /* Print prefix if ALT_FLAG is set */
                if (flags & ALT_FLAG) {
                    putchar('0');
                    putchar('x');
                }
                if (npad_bytes > strlen((char *)&nbuf)) {
                    npad_bytes -= strlen((char *)&nbuf);
                    if (flags & LEAD_ZERO)
                        for (; npad_bytes > 0; npad_bytes--) putchar('0');
                    else
                        for (; npad_bytes > 0; npad_bytes--) putchar(' ');
                }
                for (i = 0; nbuf[i] != 0; i++) putchar(nbuf[i]);
                flags = 0;
                npad_bytes = 0;
                break;
            case 'I': /* IP Addresses */
                /* Not implemented */
                /* fall through */
            case 'M': /* Ethernet MAC addresses */
                /* Not implemented */
                /* fall through */
            case 'n':
                /* Not implemented */
                break;
            default:
                putchar('%');
                putchar(c);
                break;
        }
    }
}