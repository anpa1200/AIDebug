#include "case_common.h"

LEARN uint32_t learn_logical_right(uint32_t value, uint32_t count) {
    return value >> (count & 31u);
}
