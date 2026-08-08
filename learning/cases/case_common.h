#ifndef AIDEBUG_LEARNING_CASE_COMMON_H
#define AIDEBUG_LEARNING_CASE_COMMON_H

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

#endif
