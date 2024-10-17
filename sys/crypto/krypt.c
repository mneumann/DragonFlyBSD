#include <sys/types.h>
#include <sys/param.h>
#include <sys/errno.h>
#include <sys/kernel.h>
#include <sys/malloc.h>

#include <stdbool.h>
#include <string.h>

#include "krypt.h"

#define KRYPT_FLAGS_INITIALIZED 1
#define KRYPT_FLAGS_KEY_OK	2
#define KRYPT_FLAGS_IV_OK	4

MALLOC_DEFINE(M_KRYPT_CTX, "krypt data", "crypto session records");
#define KRYPT_MALLOC(sz) kmalloc(sz, M_KRYPT_CTX, M_WAITOK)
#define KRYPT_FREE(ptr)	 kfree(ptr, M_KRYPT_CTX)

extern const struct krypt_cipher krypt_ciphers[];

const struct krypt_cipher *
krypt_find_cipher(const char *cipher_name, int keysize_in_bits)
{
	for (const struct krypt_cipher *cipherp = krypt_ciphers;
	     cipherp->name; ++cipherp) {
		if ((*cipherp->probe)(cipher_name, keysize_in_bits) ==
		    0) {
			return cipherp;
		}
	}

	return NULL;
}

int
krypt_init(krypt_session_t session, const struct krypt_cipher *cipher)
{
	if (!cipher)
		return EINVAL;
	if (session->krypt_flags != 0)
		return EINVAL;

	session->krypt_ctx = KRYPT_MALLOC(cipher->ctxsize);
	session->krypt_iv = KRYPT_MALLOC(cipher->blocksize);

	if (!session->krypt_ctx || !session->krypt_iv) {
		if (session->krypt_ctx)
			KRYPT_FREE(session->krypt_ctx);
		if (session->krypt_iv)
			KRYPT_FREE(session->krypt_iv);
		return ENOMEM;
	}

	bzero(session->krypt_ctx, cipher->ctxsize);
	bzero(session->krypt_iv, cipher->blocksize);

	session->krypt_cipher = cipher;
	session->krypt_flags |= KRYPT_FLAGS_INITIALIZED;

	return (0);
}

int
krypt_setkey(krypt_session_t session, const uint8_t *keydata,
    int keylen)
{
	if ((session->krypt_flags & KRYPT_FLAGS_INITIALIZED) == 0)
		return EINVAL;
	if (!keydata)
		return EINVAL;

	int error = (*session->krypt_cipher->setkey)(session->krypt_ctx,
	    keydata, keylen);

	if (!error)
		session->krypt_flags |= KRYPT_FLAGS_KEY_OK;
	// TODO: else unset FLAGS_KEY_OK

	return error;
}

int
krypt_setiv(krypt_session_t session, const uint8_t *ivdata, int ivlen)
{
	if ((session->krypt_flags & KRYPT_FLAGS_INITIALIZED) == 0)
		return EINVAL;
	if (!ivdata)
		return EINVAL;

	bzero(session->krypt_iv, session->krypt_cipher->ivsize);
	memcpy(session->krypt_iv, ivdata,
	    MIN(ivlen, session->krypt_cipher->ivsize));

	return (0);
}

int
krypt_encrypt(krypt_session_t session, uint8_t *data, int datalen)
{
	if ((session->krypt_flags & KRYPT_FLAGS_INITIALIZED) == 0)
		return EINVAL;
	if (!data)
		return EINVAL;
	if ((datalen % session->krypt_cipher->blocksize) != 0)
		return EINVAL;

	(*session->krypt_cipher->encrypt)(session->krypt_ctx, data,
	    datalen, session->krypt_iv);

	return (0);
}

int
krypt_decrypt(krypt_session_t session, uint8_t *data, int datalen)
{
	if ((session->krypt_flags & KRYPT_FLAGS_INITIALIZED) == 0)
		return EINVAL;
	if (!data)
		return EINVAL;
	if ((datalen % session->krypt_cipher->blocksize) != 0)
		return EINVAL;

	(*session->krypt_cipher->decrypt)(session->krypt_ctx, data,
	    datalen, session->krypt_iv);

	return (0);
}

int
krypt_free(krypt_session_t session)
{
	return EINVAL;
}

#if 0
int
main(int argn, const char **argv)
{
	struct krypt_session session;
	bzero(&session, sizeof(session));

	if (krypt_init(&session, krypt_find_cipher("null", 8)))
		printf("ERROR\n");
	else
		printf("OK\n");

	if (krypt_setkey(&session, "test", 4))
		printf("ERROR: setkey\n");

	return 0;
}
#endif
