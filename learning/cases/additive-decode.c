#include "case_common.h"

LEARN void learn_additive_decode(uint8_t *buffer, size_t count, uint8_t key) {
    for (size_t index = 0u; index < count; ++index) {
        buffer[index] = (uint8_t)(buffer[index] - key);
    }
}
