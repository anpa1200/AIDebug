#include "case_common.h"

LEARN void learn_zero_words(uint32_t *destination, size_t count) {
    for (size_t index = 0u; index < count; ++index) {
        destination[index] = 0u;
    }
}
