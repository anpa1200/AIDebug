#include "case_common.h"

LEARN uint32_t learn_lookup_table(const uint32_t *table, uint32_t index) {
    return table[index & 0xffu];
}
