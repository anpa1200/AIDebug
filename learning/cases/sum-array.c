#include "case_common.h"

LEARN uint32_t learn_sum_array(const uint32_t *values, size_t count) {
    uint32_t sum = 0;
    for (size_t index = 0; index < count; ++index) {
        sum += values[index];
    }
    return sum;
}
