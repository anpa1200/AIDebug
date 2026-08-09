#include "case_common.h"

LEARN int32_t learn_find_maximum(const int32_t *values, size_t count) {
    if (count == 0u) {
        return 0;
    }
    int32_t candidate = values[0];
    for (size_t index = 1u; index < count; ++index) {
        if (values[index] > candidate) {
            candidate = values[index];
        }
    }
    return candidate;
}
