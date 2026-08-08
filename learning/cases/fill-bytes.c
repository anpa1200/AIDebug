#include "case_common.h"

LEARN void learn_fill_bytes(uint8_t *destination, uint8_t value, size_t count) {
    for (size_t index = 0; index < count; ++index) {
        destination[index] = value;
    }
}
