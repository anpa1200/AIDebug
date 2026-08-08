#include "case_common.h"

LEARN uint64_t learn_xchg(uint32_t left, uint32_t right) {
    __asm__ volatile ("xchgl %0, %1" : "+r" (left), "+r" (right));
    return ((uint64_t)left << 32u) | right;
}
