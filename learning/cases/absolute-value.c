#include "case_common.h"

LEARN uint32_t learn_absolute_value(int32_t value) {
    return value < 0 ? 0u - (uint32_t)value : (uint32_t)value;
}
