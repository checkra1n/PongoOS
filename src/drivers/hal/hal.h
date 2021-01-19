/* 
 * pongoOS - https://checkra.in
 * 
 * Copyright (C) 2019-2020 checkra1n team
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
struct driver {
    void (*initializer)(struct driver*);
    void * context;
    const char* name;
    uint32_t flags;
};

#define DRIVER_FLAGS_DEVICE 0
#define DRIVER_FLAGS_PLATFORM 1

#define REGISTER_DRIVER(_name, _initializer, _context, _flags) \
static struct driver __attribute__((used,section("__DATA,__drivers"))) _name = { \
    .name = #_name, .initializer = _initializer, .context = _context, .flags = _flags\
};

void hal_init();
struct hal_platform;
struct hal_platform_driver {
    struct hal_platform_driver* next;
    const char* name;
    void* context;
    bool (*probe)(struct hal_platform_driver* device_driver, struct hal_platform* device);
    bool (*get_platform_value)(const char* name, void* value, size_t* size);
    void (*late_init)();
};

struct hal_device {
    struct hal_device* next;
    struct hal_device* down;
    struct hal_device* parent;
    const char* name;
    dt_node_t* node;
    struct hal_device_service* services;

    uint32_t phandle;
};

struct hal_device_service {
    struct hal_device_service* next;
    const char* name;
    struct hal_service* service;
    void* context;
};

struct hal_service {
    struct hal_service* next;
    const char* name;
    bool (*probe)(struct hal_service* svc, struct hal_device* device, void** context);
    int (*service_op)(struct hal_device_service* svc, struct hal_device* device, uint32_t method, void* data_in, size_t data_in_size, void* data_out, size_t *data_out_size);
};

extern void hal_register_hal_service(struct hal_service* svc);
extern void hal_register_phandle_device(uint32_t phandle, struct hal_device* dev);
extern struct hal_device* hal_get_phandle_device(uint32_t phandle);

struct hal_platform {
    uint32_t cpid;
    uint32_t flags;
    lock lock;
    struct hal_platform_driver* bound_platform_driver;
    struct hal_device* devices;
    struct hal_service* services;
};

extern struct hal_platform* gPlatform;
extern void hal_register_platform_driver(struct hal_platform_driver* driver);
extern const char* hal_platform_name();
extern bool hal_get_platform_value(const char* name, void* value, size_t* size);
extern int hal_invoke_service_op(struct hal_device* device, const char* svc_name, uint32_t method, void* data_in, size_t data_in_size, void* data_out, size_t *data_out_size);
extern struct hal_device * hal_get_mapper(struct hal_device* device, uint32_t index);
extern struct hal_device * hal_device_by_name(const char* name);
extern void * hal_map_registers(struct hal_device* device, uint32_t index, size_t *size);
extern int32_t hal_get_irqno(struct hal_device* device, uint32_t index);
extern uint64_t hal_map_physical_mmio(uint64_t regbase, uint64_t size);
extern int32_t hal_get_clock_gate_id(struct hal_device* device, uint32_t index);
extern int32_t hal_get_clock_gate_size(struct hal_device* device);


#define HAL_LOAD_XNU_DTREE 0
#define HAL_LOAD_DTREE_CHILDREN 1
#define HAL_CREATE_CHILD_DEVICE 2
#define HAL_GET_MAPPER 3
#define HAL_MAP_REGISTERS 4
#define HAL_GET_IRQNR 5
#define HAL_DEVICE_CLOCK_GATE_ON 6
#define HAL_DEVICE_CLOCK_GATE_OFF 7

