#include <errno.h>
#include <stddef.h>
#include <stdint.h>

#include "aes.h"
#include "aes_private.h"

int aes_a7(uint32_t op, const void *src, void *dst, size_t len, const void *iv, const void *key)
{
    return ENOSYS; // TODO
}
