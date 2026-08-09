#include "case_common.h"

LEARN int32_t learn_power_of_two(uint32_t value) {
    return value != 0u && (value & (value - 1u)) == 0u;
}
