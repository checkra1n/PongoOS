#import <pongo.h>
#import "i2c.h"

struct i2c_ops i2c_8940x_ops;

__unused static uint32_t i2c_8940x_reg_read(struct i2c_8940x_ctx* i2c, uint32_t offset) {
    uint32_t rv = *(volatile uint32_t *)(i2c->i2c_regbase + offset);
#ifdef REG_LOG
    fiprintf(stderr, "i2c_8940x_8940x_reg_read(%x) = %x\n", offset, rv);
#endif
    return rv;
}

__unused static void i2c_8940x_reg_write(struct i2c_8940x_ctx* i2c, uint32_t offset, uint32_t value) {
#ifdef REG_LOG
    fiprintf(stderr, "i2c_8940x_8940x_reg_write(%x) = %x\n", offset, rv);
#endif
    *(volatile uint32_t *)(i2c->i2c_regbase + offset) = value;
}

__unused static void i2c_8940x_reg_or(struct i2c_8940x_ctx* i2c, uint32_t offset, uint32_t value) {
#ifdef REG_LOG
    fiprintf(stderr, "i2c_8940x_reg_or(%x) = %x\n", offset, rv);
#endif
    *(volatile uint32_t *)(i2c->i2c_regbase + offset) |= value;
}

__unused static void i2c_8940x_reg_and(struct i2c_8940x_ctx* i2c, uint32_t offset, uint32_t value) {
#ifdef REG_LOG
    fiprintf(stderr, "i2c_8940x_reg_and(%x) = %x\n", offset, rv);
#endif
    *(volatile uint32_t *)(i2c->i2c_regbase + offset) &= value;
}

static bool register_8940x_i2c(struct hal_device* device, void* context) {
    // S5L8940x I2C controller
    dt_node_t* node = device->node;

    uint32_t len = 0;
    void* name = dt_prop(node, "name", &len);
    
    fiprintf(stderr, "S5L8940xI2C device found: %s\n", name);

    struct i2c_8940x_ctx* i2c = context;

    i2c->device = device;
    i2c->i2c_regbase = (uint64_t)hal_map_registers(i2c->device, 0, NULL);
    
    return true;
}

static int i2c_8940x_service_op(struct hal_device_service* svc, struct hal_device* device, uint32_t method, void* data_in, size_t data_in_size, void* data_out, size_t *data_out_size) {
    if (method == HAL_METASERVICE_START) {
        return 0;
    }
    return -1;
}

static bool i2c_8940x_probe(struct hal_service* svc, struct hal_device* device, void** context) {
    uint32_t len = 0;
    dt_node_t* node = device->node;
    if (node) {
        void* val = dt_prop(node, "device_type", &len);
        if (val && strcmp(val, "i2c") == 0) {
            char* compat = dt_prop(node, "compatible", &len);
            char* compatend = compat + len;
            
            while (compat < compatend) {
                if (strcmp(compat, "i2c,s5l8940x") == 0) {
                    *context = calloc(sizeof(struct i2c_8940x_ctx), 1);
                    if (register_8940x_i2c(device, *context)) {
                        return i2c_provide_service(device, &i2c_8940x_ops, *context);
                    }
                    return false;
                }
                compat += strlen(compat) + 1;
            }
        }
    }
    return false;
}

static struct hal_service i2c_8940x_svc = {
    .name = "i2c8940x",
    .probe = i2c_8940x_probe,
    .service_op = i2c_8940x_service_op
};

static void i2c_8940x_init(struct driver* driver) {
    hal_register_hal_service(&i2c_8940x_svc);
}

REGISTER_DRIVER(i2c_8940x, i2c_8940x_init, NULL, 0);
