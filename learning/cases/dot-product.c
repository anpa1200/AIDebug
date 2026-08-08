#include "case_common.h"

LEARN int64_t learn_dot_product(const int32_t *left, const int32_t *right, size_t count) {
    int64_t result = 0;
    for (size_t index = 0; index < count; ++index) {
        result += (int64_t)left[index] * right[index];
    }
    return result;
}
