#include "case_common.h"

LEARN uint32_t learn_rotate_right(uint32_t value, uint32_t count) {
    count &= 31u;
    return (value >> count) | (value << ((32u - count) & 31u));
}
