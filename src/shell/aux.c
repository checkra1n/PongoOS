#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <pongo.h>

int hexparse(uint8_t *buf, char *s, size_t len)
{
    for(size_t i = 0; i < len; ++i)
    {
        char c = s[2*i],
             d = s[2*i+1];
        if(!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) ||
           !((d >= '0' && d <= '9') || (d >= 'a' && d <= 'f') || (d >= 'A' && d <= 'F')))
        {
            return -1;
        }
        buf[i] = ((uint8_t)(c >= '0' && c <= '9' ? c - '0' : (c >= 'a' && c <= 'f' ? c - 'a' : c - 'A') + 10) << 4) |
                  (uint8_t)(d >= '0' && d <= '9' ? d - '0' : (d >= 'a' && d <= 'f' ? d - 'a' : d - 'A') + 10);
    }
    return 0;
}

void hexprint(uint8_t *data, size_t sz)
{
    char buf[0x61];
    for(size_t i = 0; i < sz; i += 0x30)
    {
        size_t max = sz - i > 0x30 ? 0x30 : sz - i;
        for(size_t j = 0; j < max; ++j)
        {
            uint8_t u  = data[i+j],
                    hi = (u >> 4) & 0xf,
                    lo =  u       & 0xf;
            buf[2*j]   = hi < 10 ? '0' + hi : 'a' + (hi - 10);
            buf[2*j+1] = lo < 10 ? '0' + lo : 'a' + (lo - 10);
        }
        buf[2*max] = '\0';
        iprintf("%s", buf);
    }
    iprintf("\n");
}
