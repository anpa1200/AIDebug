#include "case_common.h"

LEARN size_t learn_count_nonzero(const uint8_t *values, size_t count) {
    size_t matches = 0;
    for (size_t index = 0; index < count; ++index) {
        matches += values[index] != 0u;
    }
    return matches;
}
