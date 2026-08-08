/*
 * Trusted, non-executed learning corpus for AIDebug.
 *
 * Every marked function is compiled into an ELF shared object. AIDebug then
 * reads that artifact with its normal static-analysis, disassembly, and Ghidra
 * pipelines. The artifact is never loaded or executed.
 */
#include <stddef.h>
#include <stdint.h>

#if defined(__GNUC__) || defined(__clang__)
#define LEARN __attribute__((noinline, used, visibility("default")))
#else
#define LEARN
#endif

struct learning_pair {
    int32_t left;
    int32_t right;
    uint32_t flags;
};

/* AIDEBUG_LESSON_BEGIN load-u32 */
LEARN uint32_t learn_load_u32(const uint32_t *address) {
    return *address;
}
/* AIDEBUG_LESSON_END load-u32 */

/* AIDEBUG_LESSON_BEGIN store-u32 */
LEARN void learn_store_u32(uint32_t *address, uint32_t value) {
    *address = value;
}
/* AIDEBUG_LESSON_END store-u32 */

/* AIDEBUG_LESSON_BEGIN array-index */
LEARN uint32_t learn_array_index(const uint32_t *values, size_t index) {
    return values[index];
}
/* AIDEBUG_LESSON_END array-index */

/* AIDEBUG_LESSON_BEGIN zero-extend */
LEARN uint32_t learn_zero_extend(uint8_t value) {
    return value;
}
/* AIDEBUG_LESSON_END zero-extend */

/* AIDEBUG_LESSON_BEGIN sign-extend */
LEARN int32_t learn_sign_extend(int8_t value) {
    return value;
}
/* AIDEBUG_LESSON_END sign-extend */

/* AIDEBUG_LESSON_BEGIN swap-values */
LEARN void learn_swap_values(uint32_t *left, uint32_t *right) {
    uint32_t temporary = *left;
    *left = *right;
    *right = temporary;
}
/* AIDEBUG_LESSON_END swap-values */

/* AIDEBUG_LESSON_BEGIN add */
LEARN int32_t learn_add(int32_t left, int32_t right) {
    return left + right;
}
/* AIDEBUG_LESSON_END add */

/* AIDEBUG_LESSON_BEGIN subtract */
LEARN int32_t learn_subtract(int32_t left, int32_t right) {
    return left - right;
}
/* AIDEBUG_LESSON_END subtract */

/* AIDEBUG_LESSON_BEGIN increment */
LEARN uint32_t learn_increment(uint32_t value) {
    return value + 1u;
}
/* AIDEBUG_LESSON_END increment */

/* AIDEBUG_LESSON_BEGIN multiply */
LEARN int32_t learn_multiply(int32_t value, int32_t factor) {
    return value * factor;
}
/* AIDEBUG_LESSON_END multiply */

/* AIDEBUG_LESSON_BEGIN signed-divide */
LEARN int32_t learn_signed_divide(int32_t value, int32_t divisor) {
    return value / divisor;
}
/* AIDEBUG_LESSON_END signed-divide */

/* AIDEBUG_LESSON_BEGIN unsigned-modulo */
LEARN uint32_t learn_unsigned_modulo(uint32_t value, uint32_t divisor) {
    return value % divisor;
}
/* AIDEBUG_LESSON_END unsigned-modulo */

/* AIDEBUG_LESSON_BEGIN and-mask */
LEARN uint32_t learn_and_mask(uint32_t value) {
    return value & 0xffu;
}
/* AIDEBUG_LESSON_END and-mask */

/* AIDEBUG_LESSON_BEGIN or-flags */
LEARN uint32_t learn_or_flags(uint32_t value, uint32_t flags) {
    return value | flags;
}
/* AIDEBUG_LESSON_END or-flags */

/* AIDEBUG_LESSON_BEGIN xor-values */
LEARN uint32_t learn_xor_values(uint32_t value, uint32_t key) {
    return value ^ key;
}
/* AIDEBUG_LESSON_END xor-values */

/* AIDEBUG_LESSON_BEGIN invert-bits */
LEARN uint32_t learn_invert_bits(uint32_t value) {
    return ~value;
}
/* AIDEBUG_LESSON_END invert-bits */

/* AIDEBUG_LESSON_BEGIN shift-left */
LEARN uint32_t learn_shift_left(uint32_t value, uint32_t count) {
    return value << (count & 31u);
}
/* AIDEBUG_LESSON_END shift-left */

/* AIDEBUG_LESSON_BEGIN logical-right */
LEARN uint32_t learn_logical_right(uint32_t value, uint32_t count) {
    return value >> (count & 31u);
}
/* AIDEBUG_LESSON_END logical-right */

/* AIDEBUG_LESSON_BEGIN arithmetic-right */
LEARN int32_t learn_arithmetic_right(int32_t value, uint32_t count) {
    return value >> (count & 31u);
}
/* AIDEBUG_LESSON_END arithmetic-right */

/* AIDEBUG_LESSON_BEGIN rotate-left */
LEARN uint32_t learn_rotate_left(uint32_t value) {
    return (value << 7u) | (value >> 25u);
}
/* AIDEBUG_LESSON_END rotate-left */

/* AIDEBUG_LESSON_BEGIN equal */
LEARN int learn_equal(int32_t left, int32_t right) {
    return left == right;
}
/* AIDEBUG_LESSON_END equal */

/* AIDEBUG_LESSON_BEGIN signed-less */
LEARN int learn_signed_less(int32_t left, int32_t right) {
    return left < right;
}
/* AIDEBUG_LESSON_END signed-less */

/* AIDEBUG_LESSON_BEGIN unsigned-below */
LEARN int learn_unsigned_below(uint32_t left, uint32_t right) {
    return left < right;
}
/* AIDEBUG_LESSON_END unsigned-below */

/* AIDEBUG_LESSON_BEGIN select-value */
LEARN int32_t learn_select_value(int condition, int32_t yes, int32_t no) {
    return condition ? yes : no;
}
/* AIDEBUG_LESSON_END select-value */

/* AIDEBUG_LESSON_BEGIN absolute-value */
LEARN uint32_t learn_absolute_value(int32_t value) {
    return value < 0 ? 0u - (uint32_t)value : (uint32_t)value;
}
/* AIDEBUG_LESSON_END absolute-value */

/* AIDEBUG_LESSON_BEGIN minimum */
LEARN int32_t learn_minimum(int32_t left, int32_t right) {
    return left < right ? left : right;
}
/* AIDEBUG_LESSON_END minimum */

/* AIDEBUG_LESSON_BEGIN maximum */
LEARN int32_t learn_maximum(int32_t left, int32_t right) {
    return left > right ? left : right;
}
/* AIDEBUG_LESSON_END maximum */

/* AIDEBUG_LESSON_BEGIN clamp */
LEARN int32_t learn_clamp(int32_t value, int32_t low, int32_t high) {
    if (value < low) {
        return low;
    }
    if (value > high) {
        return high;
    }
    return value;
}
/* AIDEBUG_LESSON_END clamp */

/* AIDEBUG_LESSON_BEGIN sum-array */
LEARN uint32_t learn_sum_array(const uint32_t *values, size_t count) {
    uint32_t sum = 0;
    for (size_t index = 0; index < count; ++index) {
        sum += values[index];
    }
    return sum;
}
/* AIDEBUG_LESSON_END sum-array */

/* AIDEBUG_LESSON_BEGIN find-value */
LEARN int64_t learn_find_value(const int32_t *values, size_t count, int32_t target) {
    for (size_t index = 0; index < count; ++index) {
        if (values[index] == target) {
            return (int64_t)index;
        }
    }
    return -1;
}
/* AIDEBUG_LESSON_END find-value */

/* AIDEBUG_LESSON_BEGIN count-nonzero */
LEARN size_t learn_count_nonzero(const uint8_t *values, size_t count) {
    size_t matches = 0;
    for (size_t index = 0; index < count; ++index) {
        matches += values[index] != 0u;
    }
    return matches;
}
/* AIDEBUG_LESSON_END count-nonzero */

/* AIDEBUG_LESSON_BEGIN copy-bytes */
LEARN void learn_copy_bytes(uint8_t *destination, const uint8_t *source, size_t count) {
    for (size_t index = 0; index < count; ++index) {
        destination[index] = source[index];
    }
}
/* AIDEBUG_LESSON_END copy-bytes */

/* AIDEBUG_LESSON_BEGIN fill-bytes */
LEARN void learn_fill_bytes(uint8_t *destination, uint8_t value, size_t count) {
    for (size_t index = 0; index < count; ++index) {
        destination[index] = value;
    }
}
/* AIDEBUG_LESSON_END fill-bytes */

/* AIDEBUG_LESSON_BEGIN string-length */
LEARN size_t learn_string_length(const char *text) {
    size_t length = 0;
    while (text[length] != '\0') {
        ++length;
    }
    return length;
}
/* AIDEBUG_LESSON_END string-length */

/* AIDEBUG_LESSON_BEGIN xor-buffer */
LEARN void learn_xor_buffer(uint8_t *buffer, size_t length, uint8_t key) {
    for (size_t index = 0; index < length; ++index) {
        buffer[index] ^= key;
    }
}
/* AIDEBUG_LESSON_END xor-buffer */

/* AIDEBUG_LESSON_BEGIN checksum */
LEARN uint32_t learn_checksum(const uint8_t *buffer, size_t length) {
    uint32_t checksum = 0;
    for (size_t index = 0; index < length; ++index) {
        checksum = (checksum << 5u) - checksum + buffer[index];
    }
    return checksum;
}
/* AIDEBUG_LESSON_END checksum */

/* AIDEBUG_LESSON_BEGIN fibonacci */
LEARN uint32_t learn_fibonacci(uint32_t count) {
    uint32_t previous = 0;
    uint32_t current = 1;
    for (uint32_t index = 0; index < count; ++index) {
        uint32_t next = previous + current;
        previous = current;
        current = next;
    }
    return previous;
}
/* AIDEBUG_LESSON_END fibonacci */

/* AIDEBUG_LESSON_BEGIN factorial */
LEARN uint64_t learn_factorial(uint32_t value) {
    uint64_t result = 1;
    while (value > 1u) {
        result *= value;
        --value;
    }
    return result;
}
/* AIDEBUG_LESSON_END factorial */

/* AIDEBUG_LESSON_BEGIN switch-dispatch */
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
/* AIDEBUG_LESSON_END switch-dispatch */

/* AIDEBUG_LESSON_BEGIN structure-fields */
LEARN int32_t learn_structure_fields(const struct learning_pair *pair) {
    return pair->left + pair->right + (int32_t)(pair->flags & 1u);
}
/* AIDEBUG_LESSON_END structure-fields */

/* AIDEBUG_LESSON_BEGIN indirect-call */
LEARN int32_t learn_indirect_call(int32_t (*operation)(int32_t), int32_t value) {
    return operation(value);
}
/* AIDEBUG_LESSON_END indirect-call */

/* AIDEBUG_LESSON_BEGIN recursive-sum */
LEARN uint32_t learn_recursive_sum(uint32_t value) {
    if (value == 0u) {
        return 0u;
    }
    return value + learn_recursive_sum(value - 1u);
}
/* AIDEBUG_LESSON_END recursive-sum */

/* AIDEBUG_LESSON_BEGIN byte-swap */
LEARN uint32_t learn_byte_swap(uint32_t value) {
    return ((value & 0x000000ffu) << 24u)
        | ((value & 0x0000ff00u) << 8u)
        | ((value & 0x00ff0000u) >> 8u)
        | ((value & 0xff000000u) >> 24u);
}
/* AIDEBUG_LESSON_END byte-swap */

/* AIDEBUG_LESSON_BEGIN dot-product */
LEARN int64_t learn_dot_product(const int32_t *left, const int32_t *right, size_t count) {
    int64_t result = 0;
    for (size_t index = 0; index < count; ++index) {
        result += (int64_t)left[index] * right[index];
    }
    return result;
}
/* AIDEBUG_LESSON_END dot-product */
