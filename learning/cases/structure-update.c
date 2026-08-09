#include "case_common.h"

LEARN void learn_structure_update(
    struct learning_pair *pair,
    int32_t delta,
    uint32_t flag
) {
    pair->left += delta;
    pair->right -= delta;
    pair->flags |= flag;
}
