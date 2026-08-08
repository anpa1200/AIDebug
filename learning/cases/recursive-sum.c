#include "case_common.h"

LEARN uint32_t learn_recursive_sum(uint32_t value) {
    if (value == 0u) {
        return 0u;
    }
    return value + learn_recursive_sum(value - 1u);
}
