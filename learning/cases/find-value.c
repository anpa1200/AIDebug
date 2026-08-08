#include "case_common.h"

LEARN int64_t learn_find_value(const int32_t *values, size_t count, int32_t target) {
    for (size_t index = 0; index < count; ++index) {
        if (values[index] == target) {
            return (int64_t)index;
        }
    }
    return -1;
}
