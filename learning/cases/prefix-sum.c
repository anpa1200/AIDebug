#include "case_common.h"

LEARN void learn_prefix_sum(uint32_t *values, size_t count) {
    uint32_t total = 0u;
    for (size_t index = 0u; index < count; ++index) {
        total += values[index];
        values[index] = total;
    }
}
