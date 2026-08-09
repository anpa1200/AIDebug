#include "case_common.h"

static __attribute__((noinline)) uint32_t direct_helper(uint32_t value) {
    return (value ^ 0x5a5a5a5au) + 7u;
}

LEARN uint32_t learn_direct_call(uint32_t value) {
    return direct_helper(value);
}
