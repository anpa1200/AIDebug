#include "case_common.h"

LEARN uint32_t learn_bit_toggle(uint32_t value, uint32_t mask) {
    return value ^ mask;
}
