#include "case_common.h"

LEARN int64_t learn_sum_matrix(
    const int32_t *matrix,
    size_t rows,
    size_t columns
) {
    int64_t total = 0;
    for (size_t row = 0u; row < rows; ++row) {
        for (size_t column = 0u; column < columns; ++column) {
            total += matrix[row * columns + column];
        }
    }
    return total;
}
