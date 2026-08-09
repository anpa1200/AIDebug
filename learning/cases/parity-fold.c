#include "case_common.h"

LEARN uint32_t learn_parity_fold(uint32_t value) {
    value ^= value >> 16u;
    value ^= value >> 8u;
    value ^= value >> 4u;
    value ^= value >> 2u;
    value ^= value >> 1u;
    return value & 1u;
}
