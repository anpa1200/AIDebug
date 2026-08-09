#include "case_common.h"

LEARN uint32_t learn_stack_array(uint8_t seed) {
    volatile uint8_t local[8];
    uint32_t result = 0u;
    for (size_t index = 0u; index < 8u; ++index) {
        local[index] = (uint8_t)(seed + (uint8_t)index);
    }
    for (size_t index = 0u; index < 8u; ++index) {
        result ^= local[index];
    }
    return result;
}
