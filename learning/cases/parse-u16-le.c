#include "case_common.h"

LEARN uint16_t learn_parse_u16_le(const uint8_t *data) {
    return (uint16_t)data[0] | ((uint16_t)data[1] << 8u);
}
