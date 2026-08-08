#include "case_common.h"

LEARN int32_t learn_switch_dispatch(uint32_t operation, int32_t value) {
    switch (operation) {
        case 0: return value + 1;
        case 1: return value - 1;
        case 2: return value * 2;
        case 3: return value ^ 0x55;
        case 4: return value & 0xff;
        case 5: return value | 0x100;
        default: return -1;
    }
}
