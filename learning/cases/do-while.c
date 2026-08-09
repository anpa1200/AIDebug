#include "case_common.h"

LEARN uint32_t learn_do_while(uint32_t value) {
    uint32_t count = 0u;
    do {
        value >>= 1u;
        ++count;
    } while (value != 0u);
    return count;
}
