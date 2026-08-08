#include "case_common.h"

LEARN uint32_t learn_checksum(const uint8_t *buffer, size_t length) {
    uint32_t checksum = 0;
    for (size_t index = 0; index < length; ++index) {
        checksum = (checksum << 5u) - checksum + buffer[index];
    }
    return checksum;
}
