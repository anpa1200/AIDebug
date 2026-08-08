#include "case_common.h"

LEARN int32_t learn_arithmetic_right(int32_t value, uint32_t count) {
    return value >> (count & 31u);
}
