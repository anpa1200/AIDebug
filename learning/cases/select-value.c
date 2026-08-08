#include "case_common.h"

LEARN int32_t learn_select_value(int condition, int32_t yes, int32_t no) {
    return condition ? yes : no;
}
