#include <sys/param.h>

#include <errno.h> // sys/errno.h
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "krypt.h"

#define KRYPT_FLAGS_INITIALIZED 1
#define KRYPT_FLAGS_KEY_OK	2
#define KRYPT_FLAGS_IV_OK	4

extern const struct krypt_cipher krypt_ciphers[];

const struct krypt_cipher *
krypt_find_cipher(const char *cipher_name, int keysize_in_bits)
{
	for (const struct krypt_cipher *cipherp = krypt_ciphers;
	     cipherp->name; ++cipherp) {
		if ((*cipherp->probe)(cipher_name, keysize_in_bits) == 0) {
			return cipherp;
		}
	}

	return NULL;
}

int
krypt_init(krypt_ctx_t ctx, const struct krypt_cipher *cipher)
{
	if (!cipher)
		return EINVAL;
	if (ctx->krypt_flags != 0)
		return EINVAL;

	ctx->krypt_keyctx = malloc(cipher->keyctxsize);
	ctx->krypt_iv = malloc(cipher->blocksize);

	if (!ctx->krypt_keyctx || !ctx->krypt_iv) {
		if (ctx->krypt_keyctx)
			free(ctx->krypt_keyctx);
		if (ctx->krypt_iv)
			free(ctx->krypt_iv);
		return ENOMEM;
	}

	bzero(ctx->krypt_keyctx, cipher->keyctxsize);
	bzero(ctx->krypt_iv, cipher->blocksize);

	ctx->krypt_cipher = cipher;
	ctx->krypt_flags |= KRYPT_FLAGS_INITIALIZED;

	return (0);
}

int
krypt_setkey(krypt_ctx_t ctx, const uint8_t *keydata, int keylen)
{
	if ((ctx->krypt_flags & KRYPT_FLAGS_INITIALIZED) == 0)
		return EINVAL;
	if (!keydata)
		return EINVAL;

	int error = (*ctx->krypt_cipher->setkey)(ctx->krypt_keyctx, keydata,
	    keylen);

	if (!error)
		ctx->krypt_flags |= KRYPT_FLAGS_KEY_OK;
	// else unset FLAGS_KEY_OK

	return error;
}

int
krypt_setiv(krypt_ctx_t ctx, const uint8_t *ivdata, int ivlen)
{
	if ((ctx->krypt_flags & KRYPT_FLAGS_INITIALIZED) == 0)
		return EINVAL;
	if (!ivdata)
		return EINVAL;

	bzero(ctx->krypt_iv, ctx->krypt_cipher->blocksize);
	memcpy(ctx->krypt_iv, ivdata,
	    MIN(ivlen, ctx->krypt_cipher->blocksize));

	return (0);
}

static inline void
xor_block(uint8_t *dst, const uint8_t *src, int blocksize)
{
	for (int i = 0; i < blocksize; i++)
		dst[i] ^= src[i];
}

int
krypt_encrypt(krypt_ctx_t ctx, uint8_t *data, int datalen)
{
	if ((ctx->krypt_flags & KRYPT_FLAGS_INITIALIZED) == 0)
		return EINVAL;
	if (!data)
		return EINVAL;

	const struct krypt_cipher *cipher = ctx->krypt_cipher;
	const int blocksize = cipher->blocksize;
	uint8_t *iv = ctx->krypt_iv;

	if ((datalen % blocksize) != 0)
		return EINVAL;

	if (cipher->reinit) {
		(*cipher->reinit)(ctx->krypt_keyctx, iv);

		for (int i = 0; i < datalen; i += blocksize) {
			(*cipher->encrypt)(ctx->krypt_keyctx, data + i, iv);
		}
	} else {
		for (int i = 0; i < datalen; i += blocksize) {
			/*
			 * XOR with the IV/previous block, as
			 * appropriate.
			 */
			xor_block(data + i,
			    (i == 0) ? iv : (data + i - blocksize),
			    blocksize);

			(*cipher->encrypt)(ctx->krypt_keyctx, data + i, iv);
		}
	}

	return (0);
}

int
krypt_decrypt(krypt_ctx_t ctx, uint8_t *data, int datalen)
{
	if ((ctx->krypt_flags & KRYPT_FLAGS_INITIALIZED) == 0)
		return EINVAL;
	if (!data)
		return EINVAL;

	const struct krypt_cipher *cipher = ctx->krypt_cipher;
	const int blocksize = cipher->blocksize;
	uint8_t *iv = ctx->krypt_iv;

	if ((datalen % blocksize) != 0)
		return EINVAL;

	if (cipher->reinit) {
		(*cipher->reinit)(ctx->krypt_keyctx, iv);

		for (int i = 0; i < datalen; i += blocksize) {
			(*cipher->decrypt)(ctx->krypt_keyctx, data + i, iv);
		}
	} else {
		/*
		 * Start at the end, so we don't need to keep the
		 * encrypted block as the IV for the next block.
		 */

		for (int i = datalen - blocksize; i >= 0; i -= blocksize) {
			(*cipher->decrypt)(ctx->krypt_keyctx, data + i, iv);

			/*
			 * XOR with the IV/previous block, as appropriate
			 */
			xor_block(data + i,
			    (i == 0) ? iv : (data + i - blocksize),
			    blocksize);
		}
	}

	return (0);
}

int
krypt_free(krypt_ctx_t ctx)
{
	return EINVAL;
}

int
main(int argn, const char **argv)
{
	struct krypt_ctx ctx;
	bzero(&ctx, sizeof(ctx));

	if (krypt_init(&ctx, krypt_find_cipher("null", 8)))
		printf("ERROR\n");
	else
		printf("OK\n");

	if (krypt_setkey(&ctx, "test", 4))
		printf("ERROR: setkey\n");

	return 0;
}
