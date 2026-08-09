#include "case_common.h"

LEARN int64_t learn_binary_search(
    const int32_t *values,
    size_t count,
    int32_t target
) {
    size_t low = 0u;
    size_t high = count;

    while (low < high) {
        size_t middle = low + ((high - low) / 2u);
        int32_t candidate = values[middle];
        if (candidate == target) {
            return (int64_t)middle;
        }
        if (candidate < target) {
            low = middle + 1u;
        } else {
            high = middle;
        }
    }
    return -1;
}
