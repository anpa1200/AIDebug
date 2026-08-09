#include "case_common.h"

LEARN int32_t learn_range_check(uint32_t value, uint32_t lower, uint32_t upper) {
    return value >= lower && value <= upper;
}
