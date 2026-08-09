#include "case_common.h"

LEARN uint32_t learn_state_machine(const uint8_t *input, size_t count) {
    uint32_t state = 0u;
    for (size_t index = 0u; index < count; ++index) {
        switch (state) {
            case 0u:
                state = input[index] == (uint8_t)'A' ? 1u : 0u;
                break;
            case 1u:
                state = input[index] == (uint8_t)'B' ? 2u : 0u;
                break;
            default:
                state = input[index] == (uint8_t)'C' ? 3u : 0u;
                break;
        }
    }
    return state;
}
