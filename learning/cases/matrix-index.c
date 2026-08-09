#include "case_common.h"

LEARN int32_t learn_matrix_index(
    const int32_t *matrix,
    size_t columns,
    size_t row,
    size_t column
) {
    return matrix[row * columns + column];
}
