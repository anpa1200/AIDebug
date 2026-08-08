#include "case_common.h"

LEARN int32_t learn_clamp(int32_t value, int32_t low, int32_t high) {
    if (value < low) {
        return low;
    }
    if (value > high) {
        return high;
    }
    return value;
}
