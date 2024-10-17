#include <sys/kernel.h>

#include <crypto/rijndael/rijndael.h>
#include <string.h>

#include "krypt.h"

/**
 * --------------------------------------
 *  Utility
 * --------------------------------------
 */

static inline void
xor_block(uint8_t *dst, const uint8_t *src, int blocksize)
{
	for (int i = 0; i < blocksize; i++)
		dst[i] ^= src[i];
}

typedef void (
    *block_fn_t)(const void *ctx, uint8_t *data, uint8_t *data2);

/*
 * XOR with the IV/previous block, as appropriate.
 */
#define ENCRYPT_DATA_CBC(block_fn, ctx, data, datalen, blocksize, iv) \
	for (int i = 0; i < datalen; i += blocksize) {                \
		xor_block(data + i,                                   \
		    (i == 0) ? iv : (data + i - blocksize),           \
		    blocksize);                                       \
		block_fn(ctx, data + i, data + i);                    \
	}

/*
 * Start at the end, so we don't need to keep the
 * encrypted block as the IV for the next block.
 *
 * XOR with the IV/previous block, as appropriate
 */
#define DECRYPT_DATA_CBC(block_fn, ctx, data, datalen, blocksize, iv) \
	for (int i = datalen - blocksize; i >= 0; i -= blocksize) {   \
		block_fn(ctx, data + i, data + i);                    \
		xor_block(data + i,                                   \
		    (i == 0) ? iv : (data + i - blocksize),           \
		    blocksize);                                       \
	}

/**
 * --------------------------------------
 * Cipher null
 * --------------------------------------
 */

static int
cipher_null_probe(const char *name, int keysize_in_bits)
{
	if (strcmp(name, "null") == 0)
		return (0);
	return (-1);
}

static int
cipher_null_setkey(void *ctx, const uint8_t *keydata, int keylen)
{
	return (0);
}

static void
cipher_null_encrypt(const void *ctx, uint8_t *data, int datalen,
    const uint8_t *iv)
{
}

static void
cipher_null_decrypt(const void *ctx, uint8_t *data, int datalen,
    const uint8_t *iv)
{
}

/**
 * --------------------------------------
 * AES-CBC (Rijndael-128)
 * --------------------------------------
 */

#define AES_BLOCK_LEN 16

static int
aes_cbc_probe(const char *name, int keysize_in_bits)
{
	if (strcmp(name, "aes-cbc") != 0)
		return (-1);

	if (keysize_in_bits == 128 || keysize_in_bits == 192 ||
	    keysize_in_bits == 256)
		return (0);

	return (-1);
}

static int
aes_cbc_setkey(void *ctx, const uint8_t *keydata, int keylen)
{
	if (keylen != 16 && keylen != 24 && keylen != 32)
		return (EINVAL);

	rijndael_set_key(ctx, keydata, keylen * 8);

	return (0);
}

static void
aes_cbc_encrypt(const void *ctx, uint8_t *data, int datalen,
    const uint8_t *iv)
{
	ENCRYPT_DATA_CBC(rijndael_encrypt, ctx, data, datalen,
	    AES_BLOCK_LEN, iv);
}

static void
aes_cbc_decrypt(const void *ctx, uint8_t *data, int datalen,
    const uint8_t *iv)
{
	DECRYPT_DATA_CBC(rijndael_decrypt, ctx, data, datalen,
	    AES_BLOCK_LEN, iv);
}

/**
 *
 */

const struct krypt_cipher krypt_ciphers[3] = {
	{ "null", 4, 0, 0, cipher_null_probe, cipher_null_setkey,
	    cipher_null_encrypt, cipher_null_decrypt },

	{ "AES-CBC (Rijndael-128)", AES_BLOCK_LEN, AES_BLOCK_LEN,
	    sizeof(rijndael_ctx), aes_cbc_probe, aes_cbc_setkey,
	    aes_cbc_encrypt, aes_cbc_decrypt },

	{ NULL, 0, 0, 0, NULL, NULL, NULL, NULL }
};
