#include "case_common.h"

LEARN void learn_reverse_buffer(uint8_t *buffer, size_t count) {
    size_t left = 0u;
    size_t right = count;

    while (left < right) {
        uint8_t temporary;
        --right;
        if (left >= right) {
            break;
        }
        temporary = buffer[left];
        buffer[left] = buffer[right];
        buffer[right] = temporary;
        ++left;
    }
}
