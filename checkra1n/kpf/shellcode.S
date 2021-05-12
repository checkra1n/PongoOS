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
.globl _sandbox_shellcode
.globl _sandbox_shellcode_ptrs
.globl _sandbox_shellcode_end
.globl _sandbox_shellcode_setuid_patch
.globl _dyld_hook_shellcode
.align 2
_sandbox_shellcode:
b sandbox_shellcode_m
b amfi_execve_hook
b pre_execve_hook
vnode_getpath:
mov x19, x0
nop
mov x0, x19
ret
sandbox_shellcode_m: // deny .fsevent accesses
mov x6, x30
mov x4, x19
mov x5, x0
mov x0, x1
cbz x0, nopath
bl vnode_getpath
cbz x0, nopath
ldr x7, [x0]
adr x0, pattern
ldr x8, [x0]
mov x0, xzr
cmp x8, x7
b.ne nomatch
mov x0, #1
nomatch:
nopath:
mov x19, x4
br x6
amfi_execve_hook: // you can't kill me :P (makes sure amfi doesn't try to kill our binaries)
ldr x0, [sp, #8] // cs_flags
ldr w1, [x0]
orr w1, w1,   #0x04000000 // CS_PLATFORM_BINARY
orr w1, w1,   #0x000f // CS_VALID | CS_ADHOC | CS_GET_TASK_ALLOW | CS_INSTALLER
and w1, w1, #(~0x3f00) // clearing CS_HARD | CS_KILL | CS_CHECK_EXPIRATION | CS_RESTRICT | CS_ENFORCEMENT | CS_REQUIRE_LV
//and w1, w1, #(~0x00000000)
str w1, [x0]
mov x0, xzr
ret
// call signature
//int mpo_cred_label_update_execve_t(
//    kauth_cred_t old_cred,
//    kauth_cred_t new_cred,
//    struct proc *p,
//    struct vnode *vp,
//    off_t offset,
//    struct vnode *scriptvp,
//    struct label *vnodelabel,
//    struct label *scriptvnodelabel,
//    struct label *execlabel,
//    u_int *csflags,
//    void *macpolicyattr,
//    size_t macpolicyattrlen,
//    int *disjointp
//    );
// setuid patch
pre_execve_hook:
cbz x3, pre_execve_hook$orig
sub sp, sp, #0x400
stp x29, x30, [sp]
stp x0, x1, [sp, #0x10]
stp x2, x3, [sp, #0x20]
stp x4, x5, [sp, #0x30]
stp x6, x7, [sp, #0x40]
ldr x16, vfs
blr x16 // getting current vfs context
mov x2, x0
ldr x0, [sp, #0x28]
add x1, sp, #0x80
mov w8, #0x380
stp xzr, x8, [x1]
stp xzr, xzr, [x1, 0x10]
ldr x16, vnode // getting vnode attributes
blr x16
cbnz x0, pre_execve_hook$orig$epilog // failed so we just jump out
mov w2, #0
ldr w8, [sp, #0xcc] // va_mode
tbz w8, #11, pre_execve_hook$orig$gid
ldr w8, [sp, #0xc4] // va_uid
ldr x0, [sp, #0x18] // this is new_cred->uid
str w8, [x0, #0x18]
mov w2, #1 // Mark this as having been setuid or setgid
pre_execve_hook$orig$gid:
ldr w8, [sp, #0xcc]
tbz w8, #10, pre_execve_hook$orig$p_flags
mov w2, #1
ldr w8, [sp, #0xc8]
ldr x0, [sp, #0x18]
str w8, [x0, #0x28]
pre_execve_hook$orig$p_flags:
cbz w2, pre_execve_hook$orig$epilog // didn't change UID or GID
ldr x0, [sp, #0x20]
_sandbox_shellcode_setuid_patch:
ldr w8, [x0, #0] // Gets replaced with real offset by kpf
orr w8, w8, #0x100 // Add P_SUGID
str w8, [x0, #0] // Gets replaced with real offset by kpf
pre_execve_hook$orig$epilog:
ldp x0, x1, [sp, #0x10]
ldp x2, x3, [sp, #0x20]
ldp x4, x5, [sp, #0x30]
ldp x6, x7, [sp, #0x40]
ldp x29, x30, [sp]
add sp, sp, #0x400
pre_execve_hook$orig:
ldr x16, orig
br x16

// Function logic
// const char *dyld_path(void) {
//   void *vnode = vnode_lookup(vfs_context_current(), cr_dyld_path);
//   if (vnode) {
//     vnode_put(vnode);
//     return cr_dyld_path;
//   }
//   return dyld_path;
// }
_dyld_hook_shellcode:
sub sp, sp, #0x20
stp x29, x30, [sp]
ldr x16, vfs
blr x16
mov x3, x0
adr x0, cr_dyld_path
mov w1, #0
add x2, sp, #0x10 // &vp
ldr x16, vnode_lookup
blr x16
cbnz x0, dyld_hook$missing
ldr x0, [sp, #0x10] // vp
ldr x16, vnode_put
blr x16
adr x0, cr_dyld_path
b dyld_hook$epilog
dyld_hook$missing:
adr x0, dyld_path
dyld_hook$epilog:
ldp x29, x30, [sp]
add sp, sp, #0x20
ret

cr_dyld_path:
.string "/binpack/lib/dyld"
.align 2
dyld_path:
.string "/usr/lib/dyld"
.align 3
_sandbox_shellcode_ptrs:
orig:
.quad 0x4141413341414132
vnode:
.quad 0x4141413541414134
vfs:
.quad 0x4141413741414136
vnode_lookup:
.quad 0x4141413941414138
vnode_put:
.quad 0x4141414141414140
pattern:
.quad 0x746E65766573662E // .fsevent
_sandbox_shellcode_end:



.globl _nvram_shc
.globl _nvram_shc_end

.align 2
_nvram_shc:
// We get here from a patched ret.
// Just check for kOFVariablePermKernelOnly (0x3) and turn it into kOFVariablePermRootOnly (0x0).
cmp w0, 0x3
csel w0, wzr, w0, eq
ret
_nvram_shc_end:
