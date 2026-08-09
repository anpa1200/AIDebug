#include "case_common.h"

LEARN uint32_t learn_rolling_hash(const uint8_t *buffer, size_t count) {
    uint32_t hash = 2166136261u;
    for (size_t index = 0u; index < count; ++index) {
        hash ^= buffer[index];
        hash *= 16777619u;
    }
    return hash;
}
