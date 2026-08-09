#include "case_common.h"

LEARN uint32_t learn_extract_field(uint32_t value) {
    return (value >> 8u) & 0xffu;
}
