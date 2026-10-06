/* The part of mGBA's mgba-util/common.h that the wrapper files copied from mGBA (gbwrap/uds-*.c) use, so that they compile here
 * unchanged. */
#ifndef GBWRAP_MGBA_UTIL_COMMON_H
#define GBWRAP_MGBA_UTIL_COMMON_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
#define CXX_GUARD_START extern "C" {
#define CXX_GUARD_END }
#else
#define CXX_GUARD_START
#define CXX_GUARD_END
#endif

#define UNUSED(V) (void) (V)

#endif
