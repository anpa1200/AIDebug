#include "case_common.h"

LEARN uint32_t learn_nested_loop(uint32_t rows, uint32_t columns) {
    uint32_t total = 0u;
    for (uint32_t row = 0u; row < rows; ++row) {
        for (uint32_t column = 0u; column < columns; ++column) {
            total += row + column;
        }
    }
    return total;
}
