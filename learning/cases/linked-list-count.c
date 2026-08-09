#include "case_common.h"

struct learning_node {
    const struct learning_node *next;
    uint32_t value;
};

LEARN size_t learn_linked_list_count(const struct learning_node *node) {
    size_t count = 0u;
    while (node != NULL) {
        ++count;
        node = node->next;
    }
    return count;
}
