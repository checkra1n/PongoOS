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
#include <errno.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <mach-o/reloc.h>
#include <lzma/lzmadec.h>
#include <pongo.h>
#include <aes/aes.h>

_Noreturn void abort(void) { panic("abort()"); }
_Noreturn void __chk_fail(void) { panic("__chk_fail()"); }
_Noreturn void __stack_chk_fail(void) { panic("__stack_chk_fail()"); }
uint64_t __stack_chk_guard = 0x4141414141414141;

#if 0
void *__memset_chk (void *dest, int c, size_t n, size_t dest_len) {
     if (n > dest_len) {
         panic("__memset_chk: overflow detected");
     }
     return memset(dest,c,n);
}
void *__memcpy_chk (void *dest, const void * src, size_t n, size_t dest_len) {
     if (n > dest_len) {
         panic("__memcpy_chk: overflow detected");
     }
     return memcpy(dest,src,n);
}
void __muldc3() { panic("__muldc3"); }
void __mulsc3() { panic("__mulsc3"); }
void __muloti4() { panic("__muloti4"); }
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
#endif


__asm__
(
    ".section __DATA, __pongo_exports\n"
    ".no_dead_strip pongo$exports\n"
    "pongo$exports:\n"
);
#define STR_(x) #x
#define STR(x) STR_(x)
#define PONGO_EXPORT_RAW(name, value)       \
__asm__                                     \
(                                           \
    ".section __TEXT, __cstring\n"          \
    "1:\n"                                  \
    "    .asciz \"_" #name "\"\n"           \
    ".section __DATA, __pongo_exports\n"    \
    ".align 4\n"                            \
    "    .8byte 1b\n"                       \
    "    .8byte " #value "\n"               \
)
#define PONGO_EXPORT_RENAME(name, orig) PONGO_EXPORT_RAW(name, _ ## orig)
#define PONGO_EXPORT(name) PONGO_EXPORT_RENAME(name, name)

// ========== ========== ========== ========== Newlib ========== ========== ========== ==========
// This list has been manually curated, since we want a lot of newlib to be removed with LTO.
// Removed stuff includes:  all float/double math, wide/multibyte char support, most file operations,
//                          arc4, time functions, ctype/locale/timezone, atexit, env variables
PONGO_EXPORT(__bsd_qsort_r);
PONGO_EXPORT(__dprintf);
PONGO_EXPORT(__eprintf);
PONGO_EXPORT(__errno);
PONGO_EXPORT(__fbufsize);
PONGO_EXPORT(__flbf);
PONGO_EXPORT(__fpending);
PONGO_EXPORT(__fpurge);
PONGO_EXPORT(__freadable);
PONGO_EXPORT(__freading);
PONGO_EXPORT(__fsetlocking);
PONGO_EXPORT(__fwritable);
PONGO_EXPORT(__fwriting);
PONGO_EXPORT(__getdelim);
PONGO_EXPORT(__getline);
PONGO_EXPORT(__getreent);
PONGO_EXPORT(__itoa);
PONGO_EXPORT(__malloc_lock);
PONGO_EXPORT(__malloc_unlock);
PONGO_EXPORT(__memcpy_chk);
PONGO_EXPORT(__memmove_chk);
PONGO_EXPORT(__mempcpy_chk);
PONGO_EXPORT(__memset_chk);
PONGO_EXPORT(__sinit);
PONGO_EXPORT(__snprintf_chk);
PONGO_EXPORT(__sprintf_chk);
PONGO_EXPORT(__stpcpy_chk);
PONGO_EXPORT(__stpncpy_chk);
PONGO_EXPORT(__strcat_chk);
PONGO_EXPORT(__strcpy_chk);
PONGO_EXPORT(__strncat_chk);
PONGO_EXPORT(__strncpy_chk);
PONGO_EXPORT(__utoa);
PONGO_EXPORT(__vsnprintf_chk);
PONGO_EXPORT(__vsprintf_chk);
PONGO_EXPORT(__xpg_strerror_r);
PONGO_EXPORT(_asiprintf_r);
PONGO_EXPORT(_asniprintf_r);
PONGO_EXPORT(_asnprintf_r);
PONGO_EXPORT(_asprintf_r);
PONGO_EXPORT(_atoi_r);
PONGO_EXPORT(_atol_r);
PONGO_EXPORT(_atoll_r);
PONGO_EXPORT(_calloc_r);
PONGO_EXPORT(_close_r);
PONGO_EXPORT(_diprintf_r);
PONGO_EXPORT(_dprintf_r);
PONGO_EXPORT(_fclose_r);
PONGO_EXPORT(_fcloseall_r);
PONGO_EXPORT(_fdopen_r);
PONGO_EXPORT(_fflush_r);
PONGO_EXPORT(_fgetc_r);
PONGO_EXPORT(_fgetc_unlocked_r);
PONGO_EXPORT(_fgetpos_r);
PONGO_EXPORT(_fgets_r);
PONGO_EXPORT(_fgets_unlocked_r);
PONGO_EXPORT(_fiprintf_r);
PONGO_EXPORT(_fiscanf_r);
PONGO_EXPORT(_fmemopen_r);
PONGO_EXPORT(_fprintf_r);
PONGO_EXPORT(_fpurge_r);
PONGO_EXPORT(_fputc_r);
PONGO_EXPORT(_fputc_unlocked_r);
PONGO_EXPORT(_fputs_r);
PONGO_EXPORT(_fputs_unlocked_r);
PONGO_EXPORT(_fread_r);
PONGO_EXPORT(_fread_unlocked_r);
PONGO_EXPORT(_free_r);
PONGO_EXPORT(_fscanf_r);
PONGO_EXPORT(_fseek_r);
PONGO_EXPORT(_fseeko_r);
PONGO_EXPORT(_fsetpos_r);
PONGO_EXPORT(_fstat_r);
PONGO_EXPORT(_ftell_r);
PONGO_EXPORT(_ftello_r);
PONGO_EXPORT(_funopen_r);
PONGO_EXPORT(_fwrite_r);
PONGO_EXPORT(_fwrite_unlocked_r);
PONGO_EXPORT(_getc_r);
PONGO_EXPORT(_getc_unlocked_r);
PONGO_EXPORT(_getchar_r);
PONGO_EXPORT(_getchar_unlocked_r);
PONGO_EXPORT(_getpid_r);
PONGO_EXPORT(_iprintf_r);
PONGO_EXPORT(_isatty_r);
PONGO_EXPORT(_iscanf_r);
PONGO_EXPORT(_l64a_r);
PONGO_EXPORT(_lseek_r);
//PONGO_EXPORT(_mallinfo_r);
PONGO_EXPORT(_malloc_r);
//PONGO_EXPORT(_malloc_stats_r);
//PONGO_EXPORT(_malloc_trim_r);
//PONGO_EXPORT(_malloc_usable_size_r);
PONGO_EXPORT(_mallopt_r);
PONGO_EXPORT(_memalign_r);
//PONGO_EXPORT(_mstats_r);
PONGO_EXPORT(_open_memstream_r);
PONGO_EXPORT(_perror_r);
PONGO_EXPORT(_printf_r);
PONGO_EXPORT(_putc_r);
PONGO_EXPORT(_putc_unlocked_r);
PONGO_EXPORT(_putchar_r);
PONGO_EXPORT(_putchar_unlocked_r);
PONGO_EXPORT(_puts_r);
PONGO_EXPORT(_pvalloc_r);
PONGO_EXPORT(_read_r);
PONGO_EXPORT(_realloc_r);
PONGO_EXPORT(_reallocf_r);
//PONGO_EXPORT(_reclaim_reent);
PONGO_EXPORT(_rewind_r);
PONGO_EXPORT(_sbrk_r);
PONGO_EXPORT(_scanf_r);
PONGO_EXPORT(_siprintf_r);
PONGO_EXPORT(_siscanf_r);
PONGO_EXPORT(_sniprintf_r);
PONGO_EXPORT(_snprintf_r);
PONGO_EXPORT(_sprintf_r);
PONGO_EXPORT(_sscanf_r);
PONGO_EXPORT(_strdup_r);
PONGO_EXPORT(_strerror_r);
PONGO_EXPORT(_strndup_r);
PONGO_EXPORT(_strtoimax_r);
PONGO_EXPORT(_strtol_r);
PONGO_EXPORT(_strtoll_r);
PONGO_EXPORT(_strtoul_r);
PONGO_EXPORT(_strtoull_r);
PONGO_EXPORT(_strtoumax_r);
PONGO_EXPORT(_ungetc_r);
PONGO_EXPORT(_valloc_r);
PONGO_EXPORT(_vasiprintf_r);
PONGO_EXPORT(_vasniprintf_r);
PONGO_EXPORT(_vasnprintf_r);
PONGO_EXPORT(_vasprintf_r);
PONGO_EXPORT(_vdiprintf_r);
PONGO_EXPORT(_vdprintf_r);
PONGO_EXPORT(_vfiprintf_r);
PONGO_EXPORT(_vfiscanf_r);
PONGO_EXPORT(_vfprintf_r);
PONGO_EXPORT(_vfscanf_r);
PONGO_EXPORT(_viprintf_r);
PONGO_EXPORT(_viscanf_r);
PONGO_EXPORT(_vprintf_r);
PONGO_EXPORT(_vscanf_r);
PONGO_EXPORT(_vsiprintf_r);
PONGO_EXPORT(_vsiscanf_r);
PONGO_EXPORT(_vsniprintf_r);
PONGO_EXPORT(_vsnprintf_r);
PONGO_EXPORT(_vsprintf_r);
PONGO_EXPORT(_vsscanf_r);
PONGO_EXPORT(_write_r);
PONGO_EXPORT(a64l);
PONGO_EXPORT(abs);
PONGO_EXPORT(aligned_alloc);
PONGO_EXPORT(asiprintf);
PONGO_EXPORT(asniprintf);
PONGO_EXPORT(asnprintf);
PONGO_EXPORT(asprintf);
PONGO_EXPORT(atoi);
PONGO_EXPORT(atol);
PONGO_EXPORT(atoll);
PONGO_EXPORT(bcmp);
PONGO_EXPORT(bcopy);
PONGO_EXPORT(bsearch);
PONGO_EXPORT(bzero);
PONGO_EXPORT(calloc);
PONGO_EXPORT(category);
PONGO_EXPORT(cfree);
//PONGO_EXPORT(cleanup_glue);
PONGO_EXPORT(clearerr);
PONGO_EXPORT(clearerr_unlocked);
PONGO_EXPORT(close);
PONGO_EXPORT(diprintf);
PONGO_EXPORT(div);
PONGO_EXPORT(dprintf);
//PONGO_EXPORT(explicit_bzero);
PONGO_EXPORT(fclose);
PONGO_EXPORT(fcloseall);
PONGO_EXPORT(fdopen);
PONGO_EXPORT(feof);
PONGO_EXPORT(feof_unlocked);
PONGO_EXPORT(ferror);
PONGO_EXPORT(ferror_unlocked);
PONGO_EXPORT(fflush);
PONGO_EXPORT(fflush_unlocked);
PONGO_EXPORT(ffs);
PONGO_EXPORT(ffsl);
PONGO_EXPORT(ffsll);
PONGO_EXPORT(fgetc);
PONGO_EXPORT(fgetc_unlocked);
PONGO_EXPORT(fgetpos);
PONGO_EXPORT(fgets);
PONGO_EXPORT(fgets_unlocked);
PONGO_EXPORT(fileno);
PONGO_EXPORT(fileno_unlocked);
PONGO_EXPORT(fiprintf);
PONGO_EXPORT(fiscanf);
PONGO_EXPORT(fls);
PONGO_EXPORT(flsl);
PONGO_EXPORT(flsll);
PONGO_EXPORT(fmemopen);
//PONGO_EXPORT(fprintf);
PONGO_EXPORT(fpurge);
PONGO_EXPORT(fputc);
PONGO_EXPORT(fputc_unlocked);
PONGO_EXPORT(fputs);
PONGO_EXPORT(fputs_unlocked);
PONGO_EXPORT(fread);
PONGO_EXPORT(fread_unlocked);
PONGO_EXPORT(free);
PONGO_EXPORT(fscanf);
PONGO_EXPORT(fseek);
PONGO_EXPORT(fseeko);
PONGO_EXPORT(fsetpos);
PONGO_EXPORT(fstat);
PONGO_EXPORT(ftell);
PONGO_EXPORT(ftello);
PONGO_EXPORT(funopen);
PONGO_EXPORT(fwrite);
PONGO_EXPORT(fwrite_unlocked);
PONGO_EXPORT(getc);
PONGO_EXPORT(getc_unlocked);
PONGO_EXPORT(getchar);
PONGO_EXPORT(getchar_unlocked);
PONGO_EXPORT(getpid);
PONGO_EXPORT(getw);
PONGO_EXPORT(imaxabs);
PONGO_EXPORT(imaxdiv);
PONGO_EXPORT(index);
PONGO_EXPORT(iprintf);
PONGO_EXPORT(isalnum);
PONGO_EXPORT(isalpha);
PONGO_EXPORT(isascii);
PONGO_EXPORT(isatty);
PONGO_EXPORT(isblank);
PONGO_EXPORT(iscanf);
PONGO_EXPORT(iscntrl);
PONGO_EXPORT(isdigit);
PONGO_EXPORT(isgraph);
PONGO_EXPORT(islower);
PONGO_EXPORT(isprint);
PONGO_EXPORT(ispunct);
PONGO_EXPORT(isspace);
PONGO_EXPORT(isupper);
PONGO_EXPORT(isxdigit);
PONGO_EXPORT(itoa);
PONGO_EXPORT(l64a);
PONGO_EXPORT(labs);
PONGO_EXPORT(ldiv);
PONGO_EXPORT(llabs);
PONGO_EXPORT(lldiv);
PONGO_EXPORT(longjmp);
PONGO_EXPORT(lseek);
//PONGO_EXPORT(mallinfo);
PONGO_EXPORT(malloc);
//PONGO_EXPORT(malloc_stats);
//PONGO_EXPORT(malloc_trim);
//PONGO_EXPORT(malloc_usable_size);
PONGO_EXPORT(mallopt);
PONGO_EXPORT(memalign);
PONGO_EXPORT(memccpy);
PONGO_EXPORT(memchr);
PONGO_EXPORT(memcmp);
PONGO_EXPORT(memcpy);
PONGO_EXPORT(memmem);
PONGO_EXPORT(memmove);
PONGO_EXPORT(mempcpy);
PONGO_EXPORT(memrchr);
PONGO_EXPORT(memset);
//PONGO_EXPORT(mstats);
PONGO_EXPORT(open_memstream);
PONGO_EXPORT(perror);
//PONGO_EXPORT(printf);
PONGO_EXPORT(putc);
PONGO_EXPORT(putc_unlocked);
PONGO_EXPORT(putchar);
PONGO_EXPORT(putchar_unlocked);
PONGO_EXPORT(puts);
PONGO_EXPORT(putw);
PONGO_EXPORT(pvalloc);
PONGO_EXPORT(qsort);
PONGO_EXPORT(qsort_r);
PONGO_EXPORT(rand);
PONGO_EXPORT(rand_r);
PONGO_EXPORT(random);
PONGO_EXPORT(rawmemchr);
PONGO_EXPORT(read);
PONGO_EXPORT(realloc);
PONGO_EXPORT(reallocarray);
PONGO_EXPORT(reallocf);
PONGO_EXPORT(rewind);
PONGO_EXPORT(rindex);
PONGO_EXPORT(sbrk);
PONGO_EXPORT(scanf);
PONGO_EXPORT(setbuf);
PONGO_EXPORT(setbuffer);
PONGO_EXPORT(setjmp);
PONGO_EXPORT(setlinebuf);
PONGO_EXPORT(setvbuf);
PONGO_EXPORT(siprintf);
PONGO_EXPORT(siscanf);
PONGO_EXPORT(sniprintf);
//PONGO_EXPORT(snprintf);
PONGO_EXPORT(sprintf);
PONGO_EXPORT(srand);
PONGO_EXPORT(srandom);
PONGO_EXPORT(sscanf);
PONGO_EXPORT(stpcpy);
PONGO_EXPORT(stpncpy);
PONGO_EXPORT(strcasecmp);
PONGO_EXPORT(strcasestr);
PONGO_EXPORT(strcat);
PONGO_EXPORT(strchr);
PONGO_EXPORT(strchrnul);
PONGO_EXPORT(strcmp);
PONGO_EXPORT(strcpy);
PONGO_EXPORT(strcspn);
PONGO_EXPORT(strdup);
PONGO_EXPORT(strerror);
PONGO_EXPORT(strerror_r);
PONGO_EXPORT(strlcat);
PONGO_EXPORT(strlcpy);
PONGO_EXPORT(strlen);
PONGO_EXPORT(strlwr);
PONGO_EXPORT(strncasecmp);
PONGO_EXPORT(strncat);
PONGO_EXPORT(strncmp);
PONGO_EXPORT(strncpy);
PONGO_EXPORT(strndup);
PONGO_EXPORT(strnlen);
PONGO_EXPORT(strnstr);
PONGO_EXPORT(strpbrk);
PONGO_EXPORT(strrchr);
PONGO_EXPORT(strsep);
PONGO_EXPORT(strspn);
PONGO_EXPORT(strstr);
PONGO_EXPORT(strtoimax);
PONGO_EXPORT(strtok);
PONGO_EXPORT(strtok_r);
PONGO_EXPORT(strtol);
PONGO_EXPORT(strtoll);
PONGO_EXPORT(strtoul);
PONGO_EXPORT(strtoull);
PONGO_EXPORT(strtoumax);
PONGO_EXPORT(strupr);
PONGO_EXPORT(strverscmp);
PONGO_EXPORT(swab);
PONGO_EXPORT(tdelete);
PONGO_EXPORT(tdestroy);
PONGO_EXPORT(tfind);
//PONGO_EXPORT(timingsafe_bcmp);
//PONGO_EXPORT(timingsafe_memcmp);
PONGO_EXPORT(toascii);
PONGO_EXPORT(tolower);
PONGO_EXPORT(toupper);
PONGO_EXPORT(tsearch);
PONGO_EXPORT(twalk);
PONGO_EXPORT(ungetc);
PONGO_EXPORT(utoa);
PONGO_EXPORT(valloc);
PONGO_EXPORT(vasiprintf);
PONGO_EXPORT(vasniprintf);
PONGO_EXPORT(vasnprintf);
PONGO_EXPORT(vasprintf);
PONGO_EXPORT(vdiprintf);
PONGO_EXPORT(vdprintf);
PONGO_EXPORT(vfiprintf);
PONGO_EXPORT(vfiscanf);
//PONGO_EXPORT(vfprintf);
PONGO_EXPORT(vfscanf);
PONGO_EXPORT(viprintf);
PONGO_EXPORT(viscanf);
//PONGO_EXPORT(vprintf);
PONGO_EXPORT(vscanf);
PONGO_EXPORT(vsiprintf);
PONGO_EXPORT(vsiscanf);
PONGO_EXPORT(vsniprintf);
//PONGO_EXPORT(vsnprintf);
PONGO_EXPORT(vsprintf);
PONGO_EXPORT(vsscanf);
PONGO_EXPORT(write);

// ========== ========== ========== ========== Pongo ========== ========== ========== ==========

// DeviceTree
PONGO_EXPORT(gDeviceTree);
PONGO_EXPORT(dt_check$64);
PONGO_EXPORT(dt_parse$64);
PONGO_EXPORT(dt_find);
PONGO_EXPORT(dt_prop$64);
PONGO_EXPORT(dt_print);
PONGO_EXPORT(dt_node);
PONGO_EXPORT(dt_get);
PONGO_EXPORT(dt_node_prop);
PONGO_EXPORT(dt_get_prop$64);
PONGO_EXPORT(dt_node_u32);
PONGO_EXPORT(dt_get_u32);
PONGO_EXPORT(dt_node_u64);
PONGO_EXPORT(dt_get_u64);
PONGO_EXPORT(dt_alloc_memmap);
// DeviceTree legacy compat
PONGO_EXPORT_RENAME(dt_check, dt_check$32);
PONGO_EXPORT_RENAME(dt_parse, dt_parse$32);
PONGO_EXPORT_RENAME(dt_prop, dt_prop$32);
PONGO_EXPORT_RENAME(dt_get_prop, dt_get_prop$32);
PONGO_EXPORT(dt_get_u32_prop);
PONGO_EXPORT(dt_get_u64_prop);
PONGO_EXPORT(dt_get_u64_prop_i);

// TODO: sort & clean up, match headers
PONGO_EXPORT(xnu_pf_apply_each_kext);
PONGO_EXPORT(xnu_pf_get_first_kext);
PONGO_EXPORT(xnu_pf_get_kext_header);
PONGO_EXPORT(xnu_pf_disable_patch);
PONGO_EXPORT(xnu_pf_enable_patch);
PONGO_EXPORT(xnu_pf_ptr_to_data);
PONGO_EXPORT(xnu_pf_patchset_destroy);
PONGO_EXPORT(xnu_pf_patchset_create);
PONGO_EXPORT(print_register);
PONGO_EXPORT(alloc_static);
PONGO_EXPORT(xnu_slide_hdr_va);
PONGO_EXPORT(xnu_slide_value);
PONGO_EXPORT(xnu_header);
PONGO_EXPORT(xnu_platform);
PONGO_EXPORT(xnu_va_to_ptr);
PONGO_EXPORT(xnu_ptr_to_va);
PONGO_EXPORT(xnu_rebase_va);
PONGO_EXPORT(kext_rebase_va);
PONGO_EXPORT(xnu_pf_range_from_va);
PONGO_EXPORT(xnu_pf_segment);
PONGO_EXPORT(xnu_pf_section);
PONGO_EXPORT(xnu_pf_all);
PONGO_EXPORT(xnu_pf_all_x);
PONGO_EXPORT(xnu_pf_maskmatch);
PONGO_EXPORT(xnu_pf_emit);
PONGO_EXPORT(xnu_pf_apply);
PONGO_EXPORT(macho_get_segment);
PONGO_EXPORT(macho_get_section);
PONGO_EXPORT(event_fire);
PONGO_EXPORT(event_wait);
PONGO_EXPORT(event_wait_asserted);
//PONGO_EXPORT(bzero);
//PONGO_EXPORT(memset);
PONGO_EXPORT(memcpy_trap);
PONGO_EXPORT(free_contig);
PONGO_EXPORT(phys_reference);
PONGO_EXPORT(phys_dereference);
PONGO_EXPORT(phys_force_free);
PONGO_EXPORT(mark_phys_wired);
PONGO_EXPORT(phys_get_entry);
PONGO_EXPORT(phys_set_entry);
PONGO_EXPORT(vm_flush);
PONGO_EXPORT(vm_flush_by_addr);
PONGO_EXPORT(free_phys);
PONGO_EXPORT(vm_space_map_page_physical_prot);
PONGO_EXPORT(proc_reference);
PONGO_EXPORT(proc_release);
PONGO_EXPORT(proc_create_task);
PONGO_EXPORT(vm_deallocate);
PONGO_EXPORT(vm_allocate);
//PONGO_EXPORT(strcmp);
PONGO_EXPORT(queue_rx_string);
//PONGO_EXPORT(strlen);
//PONGO_EXPORT(strcpy);
PONGO_EXPORT(task_create);
PONGO_EXPORT(task_create_extended);
PONGO_EXPORT(task_restart_and_link);
PONGO_EXPORT(task_critical_enter);
PONGO_EXPORT(task_critical_exit);
PONGO_EXPORT(task_bind_to_irq);
PONGO_EXPORT(task_release);
PONGO_EXPORT(task_reference);
PONGO_EXPORT(tz_get);
PONGO_EXPORT(tz_set);
PONGO_EXPORT(tz_locked);
PONGO_EXPORT(tz_lock);
PONGO_EXPORT(tz_lockdown);
PONGO_EXPORT(tz_blackbird);
PONGO_EXPORT(tz0_calculate_encrypted_block_offset);
PONGO_EXPORT(vatophys);
PONGO_EXPORT(vatophys_static);
PONGO_EXPORT(lock_take);
PONGO_EXPORT(lock_take_spin);
PONGO_EXPORT(lock_release);
//PONGO_EXPORT(memmove);
//PONGO_EXPORT(memmem);
PONGO_EXPORT(memstr);
PONGO_EXPORT(memstr_partial);
//PONGO_EXPORT(memcpy);
//PONGO_EXPORT(putc);
//PONGO_EXPORT(putchar);
//PONGO_EXPORT(puts);
//PONGO_EXPORT(strtoul);
PONGO_EXPORT(invalidate_icache);
PONGO_EXPORT(task_current);
PONGO_EXPORT(task_register_irq);
PONGO_EXPORT(task_register);
PONGO_EXPORT(task_yield);
PONGO_EXPORT(task_wait);
PONGO_EXPORT(task_exit);
PONGO_EXPORT(task_switch_irq);
PONGO_EXPORT(task_exit_irq);
PONGO_EXPORT(task_switch);
PONGO_EXPORT(task_link);
PONGO_EXPORT(task_unlink);
PONGO_EXPORT(task_irq_dispatch);
PONGO_EXPORT(task_yield_asserted);
PONGO_EXPORT(task_register_unlinked);
PONGO_EXPORT(panic);
PONGO_EXPORT(abort);
PONGO_EXPORT(spin);
PONGO_EXPORT(get_ticks);
PONGO_EXPORT(usleep);
PONGO_EXPORT(sleep);
PONGO_EXPORT(wdt_reset);
PONGO_EXPORT(wdt_enable);
PONGO_EXPORT(wdt_disable);
PONGO_EXPORT(command_putc);
PONGO_EXPORT(command_puts);
PONGO_EXPORT(command_register);
PONGO_EXPORT(command_tokenize);
PONGO_EXPORT(hexparse);
PONGO_EXPORT(hexprint);
PONGO_EXPORT(get_el);
PONGO_EXPORT(cache_invalidate);
PONGO_EXPORT(cache_clean_and_invalidate);
PONGO_EXPORT(cache_clean_and_invalidate_all);
PONGO_EXPORT(register_irq_handler);
PONGO_EXPORT(device_clock_by_id);
PONGO_EXPORT(device_clock_by_name);
PONGO_EXPORT(clock_gate);
PONGO_EXPORT(disable_interrupts);
PONGO_EXPORT(enable_interrupts);
PONGO_EXPORT(alloc_contig);
PONGO_EXPORT(alloc_phys);
PONGO_EXPORT(map_physical_range);
PONGO_EXPORT(task_vm_space);
PONGO_EXPORT(usbloader_init);
PONGO_EXPORT(task_irq_teardown);
//PONGO_EXPORT(realloc);
//PONGO_EXPORT(malloc);
PONGO_EXPORT(phystokv);
//PONGO_EXPORT(free);
PONGO_EXPORT(hexdump);
//PONGO_EXPORT(memcmp);
PONGO_EXPORT(map_range);
PONGO_EXPORT(linear_kvm_alloc);
PONGO_EXPORT(vm_flush_by_addr_all_asid);
PONGO_EXPORT(vatophys_force);
PONGO_EXPORT(serial_disable_rx);
PONGO_EXPORT(serial_enable_rx);
//PONGO_EXPORT(__memset_chk);
//PONGO_EXPORT(__memcpy_chk);
PONGO_EXPORT(resize_loader_xfer_data);
PONGO_EXPORT(gBootArgs);
PONGO_EXPORT(gTopOfKernelData);
PONGO_EXPORT(gEntryPoint);
PONGO_EXPORT(gIOBase);
PONGO_EXPORT(gPMGRBase);
PONGO_EXPORT(unlzma_decompress);
PONGO_EXPORT(gDevType);
PONGO_EXPORT(soc_name);
PONGO_EXPORT(socnum);
PONGO_EXPORT(loader_xfer_recv_data);
PONGO_EXPORT(loader_xfer_recv_count);
PONGO_EXPORT(preboot_hook);
PONGO_EXPORT(ramdisk_buf);
PONGO_EXPORT(ramdisk_size);
PONGO_EXPORT(sep_boot_hook);
PONGO_EXPORT(aes);
PONGO_EXPORT(_impure_ptr);
PONGO_EXPORT(loader_xfer_recv_size);
PONGO_EXPORT(overflow_mode);
PONGO_EXPORT(gFramebuffer);
PONGO_EXPORT(gWidth);
PONGO_EXPORT(gHeight);
PONGO_EXPORT(gRowPixels);
PONGO_EXPORT(y_cursor);
PONGO_EXPORT(x_cursor);
PONGO_EXPORT(scale_factor);
PONGO_EXPORT(__chk_fail);
PONGO_EXPORT(__stack_chk_fail);
PONGO_EXPORT(__stack_chk_guard);
//PONGO_EXPORT_RENAME(iprintf, iprintf);
PONGO_EXPORT_RENAME(printf, iprintf);
//PONGO_EXPORT_RENAME(fiprintf, fiprintf);
PONGO_EXPORT_RENAME(fprintf, fiprintf);
//PONGO_EXPORT_RENAME(viprintf, viprintf);
PONGO_EXPORT_RENAME(vprintf, viprintf);
//PONGO_EXPORT_RENAME(vfiprintf, vfiprintf);
PONGO_EXPORT_RENAME(vfprintf, vfiprintf);
//PONGO_EXPORT_RENAME(sniprintf, sniprintf);
PONGO_EXPORT_RENAME(snprintf, sniprintf);
//PONGO_EXPORT_RENAME(vsniprintf, vsniprintf);
PONGO_EXPORT_RENAME(vsnprintf, vsniprintf);
__asm__
(
    ".section __DATA, __pongo_exports\n"
    ".align 4\n"
    "    .8byte 0x0\n"
    "    .8byte 0x0\n"
);

extern struct pongo_exports public_api[] __asm__("section$start$__DATA$__pongo_exports");

void link_exports(struct pongo_exports* export) {
    struct pongo_exports* api = &public_api[0];
    while (1) {
        while (api->name) {
            api++;
        }
        if (!api->name && api->value) {
            api = (struct pongo_exports*)api->value;
            continue;
        } else if (!api->name && !api->value) {
            api->value = (void*)export;
            return;
        }
    }
}
void* resolve_symbol(const char* name) {
    struct pongo_exports* api = &public_api[0];
    while (1) {
        while (api->name) {
            if (strcmp(api->name, name) == 0) {
                return api->value;
            }
            api++;
        }
        if (!api->name && api->value) {
            // we have another set of exported symbols we can walk
            api = (struct pongo_exports*)api->value;
            continue;
        }
        break;
    }
    iprintf("resolve_symbol: missing symbol: %s\n", name);
    iprintf("usbloader-linker could not load this module!!\n");
    return 0;
}
static struct pongo_module_info* head;
struct pongo_module_info* pongo_module_create(uint32_t segmentCount) {
    struct pongo_module_info* mod = calloc(sizeof (struct pongo_module_info) + sizeof(struct pongo_module_segment_info) * segmentCount, 1);
    disable_interrupts();
    mod->next = head;
    mod->segcount = segmentCount;
    head = mod;
    enable_interrupts();
    return mod;
}
void pongo_module_print_list() {
    struct pongo_module_info* cur = head;
    while (cur) {
        iprintf(" | %26s @ 0x%llx->0x%llx\n", cur->name, cur->vm_base, cur->vm_end);
        for (uint32_t i = 0; i < cur->segcount; i++) {
            iprintf(" |---> %22s @ 0x%08llx, size 0x%06llx (%s%s%s)\n", cur->segments[i].name, cur->vm_base + cur->segments[i].vm_addr, cur->segments[i].vm_size, cur->segments[i].prot & PROT_READ ? "r" : "-", cur->segments[i].prot & PROT_WRITE ? "w" : "-", cur->segments[i].prot & PROT_EXEC ? "x" : "-");
        }
        cur = cur->next;
    }
}
