#include "case_common.h"

LEARN uint32_t learn_rotate_left(uint32_t value) {
    return (value << 7u) | (value >> 25u);
}
