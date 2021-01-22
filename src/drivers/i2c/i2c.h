struct i2c_ctx;

struct i2c_tx {
    void* buf;
    uint16_t size;
    uint16_t addr;
    bool readwrite; // true = write, false = read
};

struct i2c_cmd {
    uint16_t txno;
    struct i2c_tx txes[];
};

inline static struct i2c_cmd* i2c_cmd_create(uint16_t txno) {
    struct i2c_cmd* cmd = calloc(sizeof(struct i2c_cmd) + sizeof(struct i2c_tx) * txno, 1);
    cmd->txno = txno;
    return cmd;
}

inline static void i2c_cmd_destroy(struct i2c_cmd* cmd) {
    free(cmd);
}

inline static void i2c_cmd_set_write_tx(struct i2c_cmd* cmd, uint16_t index, uint16_t address, void* base, uint16_t size) {
    cmd->txes[index].buf = base;
    cmd->txes[index].size = size;
    cmd->txes[index].addr = address;
    cmd->txes[index].readwrite = true;
}

inline static void i2c_cmd_set_read_tx(struct i2c_cmd* cmd, uint16_t index, uint16_t address, void* base, uint16_t size) {
    cmd->txes[index].buf = base;
    cmd->txes[index].size = size;
    cmd->txes[index].addr = address;
    cmd->txes[index].readwrite = false;
}

struct i2c_ops {
    bool (*i2c_command_perform)(struct i2c_ctx* ctx, struct i2c_cmd* cmd);
};

struct i2c_ctx {
    void* context;
    struct i2c_ops* ops;
};

bool i2c_provide_service(struct hal_device* device, struct i2c_ops* ops, void* context);
