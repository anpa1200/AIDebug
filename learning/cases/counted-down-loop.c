#include "case_common.h"

LEARN uint32_t learn_counted_down_loop(uint32_t count) {
    uint32_t total = 0u;
    while (count != 0u) {
        total += count;
        --count;
    }
    return total;
}
