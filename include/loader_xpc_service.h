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
#include <Foundation/Foundation.h>

#define LOADERD_SUCCESS 0
#define LOADERD_ERROR_INVALID_ACTION -1
#define LOADERD_ERROR_GENERAL 1
#define LOADERD_ERROR_ALREADY_BOOTSTRAPPED 2
#define LOADERD_ERROR_MOUNT 3
#define LOADERD_ERROR_MISSING_BOOTSTRAP 4
#define LOADERD_ERROR_TAR 5
#define LOADERD_ERROR_INVALID_DPKG_ENTRY 6
#define LOADERD_ERROR_STATUS_FILE 7
#define LOADERD_ERROR_ROOTFS_RESTORE 8
#define LOADERD_ERROR_SIGNATURE_INVALID 9
#define LOADERD_ERROR_SNAPSHOT 10
#define LOADERD_ERROR_OTA 11
#define LOADERD_NO_CONNECTION 12

#define LOADERD_ACTION_CHECK_SNAPSHOT "verify"
#define LOADERD_ACTION_BOOTSTRAP "bootstrap"
#define LOADERD_ACTION_RESTORE_ROOTFS "restore_rootfs"

static const char* loaderd_errors[] = {
    "invalid_action",                    // LOADERD_ERROR_INVALID_ACTION       -1
    "success",                           // LOADERD_SUCCESS                     0
    "general_error",                     // LOADERD_ERROR_GENERAL               1
    "device_already_bootstrapped",       // LOADERD_ERROR_ALREADY_BOOTSTRAPPED  2
    "mount_error",                       // LOADERD_ERROR_MOUNT                 3
    "missing_bootstrap",                 // LOADERD_ERROR_MISSING_BOOTSTRAP     4
    "bootstrap_extraction_error",        // LOADERD_ERROR_TAR                   5
    "invalid_dpkg_entry",                // LOADERD_ERROR_INVALID_DPKG_ENTRY    6
    "error_in_status_file",              // LOADERD_ERROR_STATUS_FILE           7
    "rootfs_restore_failed",             // LOADERD_ERROR_ROOTFS_RESTORE        8
    "bootstrap_signature_invalid",       // LOADERD_ERROR_SIGNATURE_INVALID     9
    "error_renaming_snapshot",           // LOADERD_ERROR_SNAPSHOT             10
    "error_ota",                         // LOADERD_ERROR_OTA                  11
    "error_connection",                  // LOADERD_NO_CONNECTION              12
    NULL
};


static inline const char *loaderd_strerror(int error) {
    error += 1;
    if (error < 0 || error > (sizeof(loaderd_errors)/sizeof(const char*)) - 2) {
        return "invalid_error";
    }
    return loaderd_errors[error];
}
