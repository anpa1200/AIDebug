#include "case_common.h"

LEARN size_t learn_string_length(const char *text) {
    size_t length = 0;
    while (text[length] != '\0') {
        ++length;
    }
    return length;
}
