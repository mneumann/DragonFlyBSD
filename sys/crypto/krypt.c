#include <sys/types.h>
#include <sys/param.h>
#include <sys/errno.h>
#include <sys/kernel.h>
#include <sys/malloc.h>

#include <stdbool.h>
#include <string.h>

#include "krypt.h"

extern const struct crypto_symm_cipher crypto_symm_ciphers[];

const struct crypto_symm_cipher *
crypto_symm_cipher_find(const char *algo_name, const char *mode_name,
    int keysize_in_bits)
{
	for (const struct crypto_symm_cipher *cipherp =
		 crypto_symm_ciphers;
	     cipherp->name; ++cipherp) {
		if ((*cipherp->probe)(algo_name, mode_name,
			keysize_in_bits) == 0) {
			return cipherp;
		}
	}

	return NULL;
}
