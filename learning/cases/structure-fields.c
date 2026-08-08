#include "case_common.h"

LEARN int32_t learn_structure_fields(const struct learning_pair *pair) {
    return pair->left + pair->right + (int32_t)(pair->flags & 1u);
}
