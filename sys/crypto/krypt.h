#ifndef _CRYPTO_KRYPT_H_
#define _CRYPTO_KRYPT_H_

#include <stdint.h>

struct krypt_cipher {
	const char *name;
	uint16_t blocksize;
	uint16_t keyctxsize;

	int (*probe)(const char *name, int keysize_in_bits);

	int (*setkey)(void *ctx, const uint8_t *keydata, int keylen);
	void (*reinit)(void *ctx, uint8_t *iv);
	void (*encrypt)(void *ctx, uint8_t *data, const uint8_t *iv);
	void (*decrypt)(void *ctx, uint8_t *data, const uint8_t *iv);
};

struct krypt_ctx {
	int krypt_flags;
	const struct krypt_cipher *krypt_cipher;
	void *krypt_keyctx;
	uint8_t *krypt_iv;
};

typedef struct krypt_ctx *krypt_ctx_t;

const struct krypt_cipher *krypt_find_cipher(const char *cipher_name,
    int keysize_in_bits);

int krypt_init(krypt_ctx_t ctx, const struct krypt_cipher *cipher);
int krypt_setkey(krypt_ctx_t ctx, const uint8_t *keydata, int keylen);
int krypt_setiv(krypt_ctx_t ctx, const uint8_t *ivdata, int ivlen);
int krypt_encrypt(krypt_ctx_t ctx, uint8_t *data, int datalen);
int krypt_decrypt(krypt_ctx_t ctx, uint8_t *data, int datalen);
int krypt_free(krypt_ctx_t ctx);

#endif
