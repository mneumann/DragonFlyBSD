#include <sys/kernel.h>

#include <crypto/rijndael/rijndael.h>
#include <string.h>

#include "krypt.h"

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
cipher_null_encrypt(void *ctx, uint8_t *data, const uint8_t *iv)
{
}

static void
cipher_null_decrypt(void *ctx, uint8_t *data, const uint8_t *iv)
{
}

/**
 * --------------------------------------
 * AES-CBC (Rijndael-128)
 * --------------------------------------
 */

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
aes_cbc_encrypt(void *ctx, uint8_t *data, const uint8_t *iv)
{
	rijndael_encrypt((rijndael_ctx *)ctx, data, data);
}

static void
aes_cbc_decrypt(void *ctx, uint8_t *data, const uint8_t *iv)
{
	rijndael_decrypt((rijndael_ctx *)ctx, data, data);
}


/**
 *
 */

#define AES_BLOCK_LEN 16

const struct krypt_cipher krypt_ciphers[3] = {
	{ "null", 4, 0, 0, cipher_null_probe, cipher_null_setkey, NULL,
	    cipher_null_encrypt, cipher_null_decrypt },

	{ "AES-CBC (Rijndael-128)", AES_BLOCK_LEN, AES_BLOCK_LEN,
	    sizeof(rijndael_ctx), aes_cbc_probe, aes_cbc_setkey, NULL,
	    aes_cbc_encrypt, aes_cbc_decrypt },

	{ NULL, 0, 0, 0, NULL, NULL, NULL, NULL, NULL }
};
