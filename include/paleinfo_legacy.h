#ifndef PALEINFO_LEGACY_H
#define PALEINFO_LEGACY_H

#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>

#define MAX_BOOTARGS_LEN 256

#define checkrain_option_none               0x00000000
#define checkrain_option_all                0x7fffffff
#define checkrain_option_failure            0x80000000

// Host options
#define checkrain_option_verbose_logging    (1 << 0)
#define checkrain_option_demote             (1 << 1)
#define checkrain_option_early_exit         (1 << 2)
#define checkrain_option_quick_mode         (1 << 3)
#define checkrain_option_pongo_shell        (1 << 4)
#define checkrain_option_pongo_full         (1 << 5)

// KPF options
#define checkrain_option_verbose_boot       (1 << 0)

// Global options
#define checkrain_option_safemode           (1 << 0)
#define checkrain_option_bind_mount         (1 << 1)
#define checkrain_option_overlay            (1 << 2)
#define checkrain_option_force_revert       (1 << 7) /* keep this at 7 */

// palera1n options
#define palerain1_option_rootful              (1 << 0) /* rootful jailbreak */
#define palerain1_option_jbinit_log_to_file   (1 << 1) /* log to /cores/jbinit.log */
#define palerain1_option_setup_rootful        (1 << 2) /* create fakefs */
//#define palerain1_option_setup_rootful_forced (1 << 3) /* create fakefs over an existing one */
#define palerain1_option_setup_partial_root   (1 << 4) /* fakefs creating should be partial */
// #define palerain1_option_checkrain_is_clone   (1 << 5) /* supplied checkra1n is checkra1n clone */
#define palerain1_option_rootless_livefs      (1 << 6) /* mount root livefs on rootless */
/* reserved values */
// #define palerain1_option_no_ssv               (1 << 7) /* no signed system volume */
// #define palerain1_option_force_fakefs         (1 << 8) /* force fakefs, even without SSV */
// #define palerain1_option_rootless             (1 << 9) /* rootless jailbreak */
#define palerain1_option_clean_fakefs        (1 << 10) /* clean fakefs, but does not delete it */

#define PALEINFO_MAGIC 'PLSH'

typedef uint32_t checkrain_option_t, *checkrain_option_p;

typedef enum {
    jailbreak_capability_tfp0               = 1 << 0,
    jailbreak_capability_userspace_reboot   = 1 << 1,
    jailbreak_capability_dyld_ignore_os     = 1 << 2, // TODO: This needs a better name
} jailbreak_capability_t, *jailbreak_capability_p;

#define DEFAULT_CAPABILITIES (jailbreak_capability_tfp0|jailbreak_capability_userspace_reboot)
struct kerninfo {
    uint64_t size;
    uint64_t base;
    uint64_t slide;
    checkrain_option_t flags;
};
struct paleinfo1 {
    uint32_t magic; // 'PLSH' / 0x504c5348
    uint32_t version; // 1
    checkrain_option_t flags;
    char rootdev[0x10];
};
struct kpfinfo {
    struct kerninfo k;
    checkrain_option_t kpf_flags;
    char bootargs[MAX_BOOTARGS_LEN];
};

struct new_old_info_mapping {
    uint64_t new_info;
    uint32_t old_info;
};

#define checkrain_set_option(options, option, enabled) do { \
    if (enabled)                                            \
        options = (checkrain_option_t)(options | option);   \
    else                                                    \
        options = (checkrain_option_t)(options & ~option);  \
} while (0);

static inline bool checkrain_option_enabled(checkrain_option_t flags, checkrain_option_t opt)
{
    if(flags == checkrain_option_failure)
    {
        switch(opt)
        {
            case checkrain_option_safemode:
                return true;
            default:
                return false;
        }
    }
    return (flags & opt) != 0;
}

#endif
