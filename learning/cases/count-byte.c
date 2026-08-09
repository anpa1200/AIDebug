#include "case_common.h"

LEARN size_t learn_count_byte(const uint8_t *buffer, size_t count, uint8_t target) {
    size_t matches = 0u;
    for (size_t index = 0u; index < count; ++index) {
        matches += buffer[index] == target;
    }
    return matches;
}
