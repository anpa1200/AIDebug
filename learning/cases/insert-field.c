#include "case_common.h"

LEARN uint32_t learn_insert_field(uint32_t value, uint32_t field) {
    return (value & ~(0xffu << 8u)) | ((field & 0xffu) << 8u);
}
