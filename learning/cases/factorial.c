#include "case_common.h"

LEARN uint64_t learn_factorial(uint32_t value) {
    uint64_t result = 1;
    while (value > 1u) {
        result *= value;
        --value;
    }
    return result;
}
