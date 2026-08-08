#include "case_common.h"

LEARN void learn_xor_buffer(uint8_t *buffer, size_t length, uint8_t key) {
    for (size_t index = 0; index < length; ++index) {
        buffer[index] ^= key;
    }
}
