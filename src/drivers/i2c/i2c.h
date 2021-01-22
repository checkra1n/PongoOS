struct i2c_8940x_ctx {
    uint64_t i2c_regbase;
    struct hal_device* device;
};

struct i2c_ops {

};

struct i2c_ctx {
    void* context;
    struct i2c_ops* ops;
};

bool i2c_provide_service(struct hal_device* device, struct i2c_ops* ops, void* context);
