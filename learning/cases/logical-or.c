#include "case_common.h"

LEARN int32_t learn_logical_or(uint32_t left, uint32_t right) {
    return left != 0u || right != 0u;
}
