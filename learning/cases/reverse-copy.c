#include "case_common.h"

LEARN void learn_reverse_copy(
    uint8_t *destination,
    const uint8_t *source,
    size_t count
) {
    for (size_t index = 0u; index < count; ++index) {
        destination[index] = source[count - index - 1u];
    }
}
