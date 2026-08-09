#include "case_common.h"

LEARN uint32_t learn_average_pair(uint32_t left, uint32_t right) {
    return (left & right) + ((left ^ right) >> 1u);
}
