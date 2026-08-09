#include "case_common.h"

LEARN uint32_t learn_crc_step(uint32_t state) {
    for (uint32_t bit = 0u; bit < 8u; ++bit) {
        if ((state & 1u) != 0u) {
            state = (state >> 1u) ^ 0xedb88320u;
        } else {
            state >>= 1u;
        }
    }
    return state;
}
