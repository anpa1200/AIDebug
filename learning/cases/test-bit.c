#include "case_common.h"

LEARN int32_t learn_test_bit(uint32_t value, uint32_t mask) {
    return (value & mask) != 0u;
}
