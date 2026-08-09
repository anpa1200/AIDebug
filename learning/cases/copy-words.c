#include "case_common.h"

LEARN void learn_copy_words(
    uint32_t *destination,
    const uint32_t *source,
    size_t count
) {
    for (size_t index = 0u; index < count; ++index) {
        destination[index] = source[index];
    }
}
