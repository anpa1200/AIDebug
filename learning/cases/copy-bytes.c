#include "case_common.h"

LEARN void learn_copy_bytes(uint8_t *destination, const uint8_t *source, size_t count) {
    for (size_t index = 0; index < count; ++index) {
        destination[index] = source[index];
    }
}
