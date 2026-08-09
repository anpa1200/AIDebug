#include "case_common.h"

LEARN void learn_xor_key_cycle(
    uint8_t *buffer,
    size_t count,
    const uint8_t *key,
    size_t key_length
) {
    if (key_length == 0u) {
        return;
    }
    for (size_t index = 0u; index < count; ++index) {
        buffer[index] ^= key[index % key_length];
    }
}
