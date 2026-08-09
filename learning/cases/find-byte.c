#include "case_common.h"

LEARN int64_t learn_find_byte(const uint8_t *buffer, size_t count, uint8_t target) {
    for (size_t index = 0u; index < count; ++index) {
        if (buffer[index] == target) {
            return (int64_t)index;
        }
    }
    return -1;
}
