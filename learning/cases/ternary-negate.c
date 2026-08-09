#include "case_common.h"

LEARN uint32_t learn_ternary_negate(uint32_t value, int32_t negative) {
    return negative != 0 ? 0u - value : value;
}
