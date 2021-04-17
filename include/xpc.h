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
#ifndef __XPC_H__
#define __XPC_H__

#include <stdint.h>
#include <dispatch/dispatch.h>

#define XPC_TYPE_DICTIONARY (&_xpc_type_dictionary)
extern const struct _xpc_type_s _xpc_type_dictionary;

#define XPC_ERROR_KEY_DESCRIPTION _xpc_error_key_description
extern const char *const _xpc_error_key_description;

#define XPC_TYPE_ERROR (&_xpc_type_error)
extern const struct _xpc_type_s _xpc_type_error;

#define XPC_TYPE_INT64 (&_xpc_type_int64)
extern const struct _xpc_type_s _xpc_type_int64;

typedef struct _xpc_type_s* xpc_type_t;
typedef void* xpc_object_t;
typedef void* xpc_connection_t;
typedef void* xpc_endpoint_t;
typedef void (^xpc_handler_t)(xpc_object_t);
typedef void (*xpc_finalizer_t)(void*);

#define XPC_CONNECTION_MACH_SERVICE_PRIVILEGED (1 << 1)
xpc_connection_t xpc_connection_create_mach_service(const char *name, dispatch_queue_t targetq, uint64_t flags);

xpc_connection_t xpc_connection_create_from_endpoint(xpc_endpoint_t);
void xpc_connection_set_event_handler(xpc_connection_t, xpc_handler_t);
char* xpc_copy_description(xpc_object_t);
void xpc_connection_resume(xpc_connection_t);
xpc_object_t xpc_dictionary_create(const char* const*, xpc_object_t*, size_t);
void xpc_dictionary_set_value(xpc_object_t, const char*, xpc_object_t);
xpc_object_t xpc_dictionary_get_value(xpc_object_t, const char*);
void xpc_dictionary_set_string(xpc_object_t, const char*, const char*);
void xpc_connection_send_message_with_reply(xpc_connection_t, xpc_object_t, dispatch_queue_t, xpc_handler_t);
void xpc_connection_cancel(xpc_connection_t);
xpc_type_t xpc_get_type(xpc_object_t);
int64_t xpc_int64_get_value(xpc_object_t);
xpc_object_t xpc_array_create(const xpc_object_t, size_t);
#define XPC_ARRAY_APPEND ((size_t)(-1))
void xpc_array_set_string(xpc_object_t, size_t, const char*);
char *xpc_array_get_string(xpc_object_t, size_t);
size_t xpc_array_get_count(xpc_object_t);
pid_t xpc_connection_get_pid(xpc_connection_t);
char *xpc_dictionary_get_string(xpc_object_t, const char*);
int64_t xpc_dictionary_get_int64(xpc_object_t, const char*);
uint64_t xpc_dictionary_get_uint64(xpc_object_t, const char*);
xpc_object_t xpc_retain(xpc_object_t);
xpc_object_t xpc_dictionary_create_reply(xpc_object_t);
void xpc_release(xpc_object_t);
void xpc_dictionary_set_uint64(xpc_object_t, const char*, uint64_t);
void xpc_dictionary_set_bool(xpc_object_t, const char*, bool);
void xpc_connection_send_message(xpc_connection_t, xpc_object_t);
xpc_connection_t xpc_dictionary_get_remote_connection(xpc_object_t);
xpc_connection_t xpc_connection_create(const char*, dispatch_queue_t);
xpc_endpoint_t xpc_endpoint_create(xpc_connection_t);
void xpc_connection_set_context(xpc_connection_t, void*);
void xpc_connection_set_finalizer_f(xpc_connection_t, xpc_finalizer_t);
void xpc_dictionary_set_data(xpc_object_t, const char*, const void*, size_t);
void xpc_dictionary_set_data(xpc_object_t, const char*, const void*, size_t);
const void * xpc_dictionary_get_data(xpc_object_t, const char *, size_t *);
#endif
