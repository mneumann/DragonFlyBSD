#ifndef _CRYPTO_KRYPT_H_
#define _CRYPTO_KRYPT_H_

#include <crypto/rijndael/rijndael.h>
#include <stdint.h>

struct crypto_symm_cipher_context {
	union {
		rijndael_ctx ctx;
	} ctx;
};

struct crypto_symm_cipher_iv {
	// TODO
	uint8_t _iv[64];
};

struct crypto_symm_cipher {
	const char *name;
	uint16_t blocksize;
	uint16_t ivsize;
	uint16_t ctxsize;

	int (*probe)(const char *algo_name, const char *mode_name,
	    int keysize_in_bits);

	int (*setkey)(struct crypto_symm_cipher_context *ctx,
	    const uint8_t *keydata, int keylen);

	int (*encrypt)(const struct crypto_symm_cipher_context *ctx,
	    uint8_t *data, int datalen,
	    struct crypto_symm_cipher_iv *iv);

	int (*decrypt)(const struct crypto_symm_cipher_context *ctx,
	    uint8_t *data, int datalen,
	    struct crypto_symm_cipher_iv *iv);
};

const struct crypto_symm_cipher *
crypto_symm_cipher_find(const char *algo_name, const char *mode_name,
    int keysize_in_bits);

#endif
