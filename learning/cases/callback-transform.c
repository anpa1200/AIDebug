#include "case_common.h"

typedef uint32_t (*learning_transform)(uint32_t value);

LEARN void learn_callback_transform(
    uint32_t *values,
    size_t count,
    learning_transform transform
) {
    for (size_t index = 0u; index < count; ++index) {
        values[index] = transform(values[index]);
    }
}
