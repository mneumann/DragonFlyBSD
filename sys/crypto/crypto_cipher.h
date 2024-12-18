#ifndef _CRYPTO_CIPHER_H_
#define _CRYPTO_CIPHER_H_

#include <crypto/rijndael/rijndael.h>

struct crypto_cipher_context {
	union {
		rijndael_ctx ctx;
	} ctx;
};

struct crypto_cipher_iv {
	// TODO
	uint8_t _iv[64];
};

typedef int (
    *crypto_cipher_blockfn_t)(const struct crypto_cipher_context *ctx,
    uint8_t *data, int datalen, struct crypto_cipher_iv *iv);

struct crypto_cipher {
	const char *shortname;
	const char *description;
	uint16_t blocksize;
	uint16_t ivsize;
	uint16_t ctxsize;

	int (*probe)(const char *algo_name, const char *mode_name,
	    int keysize_in_bits);

	int (*setkey)(struct crypto_cipher_context *ctx,
	    const uint8_t *keydata, int keylen);

	crypto_cipher_blockfn_t encrypt;
	crypto_cipher_blockfn_t decrypt;
};

const struct crypto_cipher *crypto_cipher_find(const char *algo_name,
    const char *mode_name, int keysize_in_bits);

#endif
