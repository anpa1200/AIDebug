#include "case_common.h"

LEARN uint32_t learn_saturating_add(uint32_t left, uint32_t right) {
    uint32_t result = left + right;
    if (result < left) {
        return UINT32_MAX;
    }
    return result;
}
