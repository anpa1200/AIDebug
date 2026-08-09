#include "case_common.h"

LEARN uint32_t learn_align_up(uint32_t value, uint32_t alignment) {
    uint32_t mask = alignment - 1u;
    return (value + mask) & ~mask;
}
