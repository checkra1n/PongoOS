
#include "kpf.h"
#include <pongo.h>
#include <xnu/xnu.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

bool found_spawn_validate_persona = false;
bool spawn_validate_persona_callback(struct xnu_pf_patch *patch, uint32_t *opcode_stream) {
    if (found_spawn_validate_persona)
        panic_at(opcode_stream, "spawn_validate_persona: Found twice!");
    puts("KPF: Found spawn_validate_persona");
    found_spawn_validate_persona = true;
    opcode_stream[3] = NOP;
    opcode_stream[5] = NOP;
    return true;
}

void kpf_spawn_validate_persona_patch(xnu_pf_patchset_t* patchset) {
    if (gKernelVersion.xnuMajor < 11215) return;

    // Since iOS 18.0, there is a check in spawn_validate_persona to forbid non-root
    // callers to spawn root processes, we patch the check for uid == 0 and gid == 0
    // for the processe to be spawned out
    // /x 001a40b900000034000a40b900000034000e40b900000034:10feffff100000ff10feffff100000ff10feffff100000ff
    uint64_t matches[] = {
        0xb9401a00, // ldr w{0-15}, [x{16-31}, #0x18]
        0x34000000, // cbz w{0-15}, ...  <---- caller uid check
        0xb9400a00, // ldr w{0-15}, [x{16-31}, #0x8]
        0x34000000, // cbz w{0-15}, ...  <---- wanted uid check
        0xb9400e00, // ldr w{0-15}, [x{16-31}, #0xc]
        0x34000000  // cbz w{0-15}, ...  <---- wanted gid check
    };

    uint64_t masks[] = {
        0xfffffe10,
        0xff000010,
        0xfffffe10,
        0xff000010,
        0xfffffe10,
        0xff000010,
    };

    xnu_pf_maskmatch(patchset, "spawn_validate_persona", matches, masks, sizeof(matches)/sizeof(uint64_t), true, (void*)spawn_validate_persona_callback);
}

kpf_component_t kpf_spawn_validate_persona =
{
    .patches =
    {
        { NULL, "__TEXT_EXEC", "__text", XNU_PF_ACCESS_32BIT, kpf_spawn_validate_persona_patch },
        {},
    },
};
