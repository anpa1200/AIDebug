#include "case_common.h"

LEARN int32_t learn_compare_buffers(
    const uint8_t *left,
    const uint8_t *right,
    size_t count
) {
    for (size_t index = 0u; index < count; ++index) {
        if (left[index] != right[index]) {
            return (int32_t)left[index] - (int32_t)right[index];
        }
    }
    return 0;
}
