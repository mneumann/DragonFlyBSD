#ifndef _CRYPTO_KRYPT_H_
#define _CRYPTO_KRYPT_H_

#include <stdint.h>

struct krypt_cipher {
	const char *name;
	uint16_t blocksize;
	uint16_t ivsize;
	uint16_t ctxsize;

	int (*probe)(const char *name, int keysize_in_bits);

	int (*setkey)(void *ctx, const uint8_t *keydata, int keylen);
	void (*encrypt)(const void *ctx, uint8_t *data, int datalen,
	    uint8_t *iv);
	void (*decrypt)(const void *ctx, uint8_t *data, int datalen,
	    uint8_t *iv);
};

struct krypt_session {
	int krypt_flags;
	const struct krypt_cipher *krypt_cipher;
	void *krypt_ctx;
	uint8_t *krypt_iv;
};

typedef struct krypt_session *krypt_session_t;

const struct krypt_cipher *krypt_find_cipher(const char *cipher_name,
    int keysize_in_bits);

int krypt_init(krypt_session_t session,
    const struct krypt_cipher *cipher);
int krypt_setkey(krypt_session_t session, const uint8_t *keydata,
    int keylen);
int krypt_setiv(krypt_session_t session, const uint8_t *ivdata,
    int ivlen);
int krypt_encrypt(krypt_session_t session, uint8_t *data, int datalen);
int krypt_decrypt(krypt_session_t session, uint8_t *data, int datalen);
int krypt_free(krypt_session_t session);

#endif
