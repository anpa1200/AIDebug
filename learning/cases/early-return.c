#include "case_common.h"

LEARN uint32_t learn_early_return(uint32_t value, uint32_t fallback) {
    if (value == 0u) {
        return fallback;
    }
    return value * 3u;
}
