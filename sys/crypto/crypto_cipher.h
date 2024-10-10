#ifndef _CRYPTO_CIPHER_H_
#define _CRYPTO_CIPHER_H_

#include <crypto/aesni/aesni.h>
#include <crypto/rijndael/rijndael.h>

struct aes_xts_ctx {
	rijndael_ctx key1;
	rijndael_ctx key2;
};

struct crypto_cipher_context {
	union {
		rijndael_ctx _rijndael;
		aesni_ctx _aesni;
		struct aes_xts_ctx _aes_xts;
	} _ctx;
};

struct crypto_cipher_iv {
	union {
		uint8_t _rijndael[16];
		aesni_iv _aesni;
		uint8_t _aes_xts[16]; /* 16 bytes are used, but the last 8 bytes
					 are zero */
	} _iv;
};

typedef int (*crypto_cipher_blockfn_t)(const struct crypto_cipher_context *ctx,
    uint8_t *data, int datalen, struct crypto_cipher_iv *iv);

typedef int (*crypto_cipher_probe_t)(const char *algo_name,
    const char *mode_name, int keysize_in_bits);

typedef int (*crypto_cipher_setkey_t)(struct crypto_cipher_context *ctx,
    const uint8_t *keydata, int keylen_in_bytes);

struct crypto_cipher {
	const char *shortname;
	const char *description;
	uint16_t blocksize;
	uint16_t ivsize;
	uint16_t ctxsize;

	crypto_cipher_probe_t probe;
	crypto_cipher_setkey_t setkey;
	crypto_cipher_blockfn_t encrypt;
	crypto_cipher_blockfn_t decrypt;
};

const struct crypto_cipher *crypto_cipher_find(const char *algo_name,
    const char *mode_name, int keysize_in_bits);

#endif
