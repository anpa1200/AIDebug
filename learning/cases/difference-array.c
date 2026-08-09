#include "case_common.h"

LEARN void learn_difference_array(
    uint32_t *output,
    const uint32_t *input,
    size_t count
) {
    for (size_t index = 1u; index < count; ++index) {
        output[index - 1u] = input[index] - input[index - 1u];
    }
}
