#include "case_common.h"

LEARN int32_t learn_indirect_call(int32_t (*operation)(int32_t), int32_t value) {
    return operation(value);
}
