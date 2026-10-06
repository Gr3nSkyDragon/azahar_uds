/* mGBA's MD5 interface (mgba-util/md5.h), as the wrapper's Pia HMAC (uds-pia.c) uses it, on top of the ESP32's ROM MD5. */
#ifndef GBWRAP_MGBA_UTIL_MD5_H
#define GBWRAP_MGBA_UTIL_MD5_H

#include <stddef.h>
#include <stdint.h>

#include "esp_rom_md5.h"

/* The ROM's header has a struct MD5Context of its own (its md5_context_t): mGBA's name is mapped to another. */
#define MD5Context GbwrapMD5Context

struct MD5Context {
	md5_context_t rom;
	uint8_t digest[16];
};

static inline void md5Init(struct MD5Context* ctx) {
	esp_rom_md5_init(&ctx->rom);
}

static inline void md5Update(struct MD5Context* ctx, const void* input, size_t len) {
	esp_rom_md5_update(&ctx->rom, input, (uint32_t) len);
}

static inline void md5Finalize(struct MD5Context* ctx) {
	esp_rom_md5_final(ctx->digest, &ctx->rom);
}

static inline void md5Buffer(const void* input, size_t len, uint8_t* result) {
	struct MD5Context ctx;
	md5Init(&ctx);
	md5Update(&ctx, input, len);
	md5Finalize(&ctx);
	for (int i = 0; i < 16; ++i) {
		result[i] = ctx.digest[i];
	}
}

#endif
