#include "case_common.h"

LEARN uint32_t learn_parse_u32_be(const uint8_t *data) {
    return ((uint32_t)data[0] << 24u)
        | ((uint32_t)data[1] << 16u)
        | ((uint32_t)data[2] << 8u)
        | (uint32_t)data[3];
}
