/*-
 * Copyright (c) 2010 Konstantin Belousov <kib@FreeBSD.org>
 * Copyright (c) 2010 Pawel Jakub Dawidek <pjd@FreeBSD.org>
 * Copyright (c) 2024 Michael Neumann <mneumann@ntecs.de>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 * the documentation and/or other materials provided with the
 * distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS AND CONTRIBUTORS ``AS IS''
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * $FreeBSD: src/sys/crypto/aesni/aesni_wrap.c,v 1.7 2010/11/27 15:41:44
 * kib Exp $
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/sysctl.h>

#include <crypto/aesni/aesni.h>
#include <crypto/crypto_cipher.h>

static int aesni_disable = 0;
// TUNABLE_INT("hw.aesni_disable", &aesni_disable);
SYSCTL_INT(_hw, OID_AUTO, aesni_disable, CTLFLAG_RW, &aesni_disable, 0, "Disable AESNI");

/*
 * Internal functions, implemented in assembler.
 */
void aesni_enc(int rounds, const uint8_t *key_schedule,
    const uint8_t from[AES_BLOCK_LEN], uint8_t to[AES_BLOCK_LEN],
    const uint8_t iv[AES_BLOCK_LEN]);
void aesni_dec(int rounds, const uint8_t *key_schedule,
    const uint8_t from[AES_BLOCK_LEN], uint8_t to[AES_BLOCK_LEN],
    const uint8_t iv[AES_BLOCK_LEN]);
void aesni_set_enckey(const uint8_t *userkey, uint8_t *encrypt_schedule,
    int number_of_rounds);
void aesni_set_deckey(const uint8_t *encrypt_schedule,
    uint8_t *decrypt_schedule, int number_of_rounds);
void aesni_decrypt_cbc(int rounds, const void *key_schedule, size_t len,
    const uint8_t *from, const uint8_t iv[AES_BLOCK_LEN]);

static inline void
aesni_encrypt_cbc(int rounds, const void *key_schedule, size_t len,
    const uint8_t *from, uint8_t *to, const uint8_t iv[AES_BLOCK_LEN])
{
	const uint8_t *ivp;
	size_t i;

	len /= AES_BLOCK_LEN;
	ivp = iv;
	for (i = 0; i < len; i++) {
		aesni_enc(rounds - 1, key_schedule, from, to, ivp);
		ivp = to;
		from += AES_BLOCK_LEN;
		to += AES_BLOCK_LEN;
	}
}

#define AESNI_CTX(ctx) (ctx->_ctx._aesni)
#define AESNI_IV(iv)   (iv->_iv._aesni.iv)

// TODO: how to improve alignment?
#define AESNI_ALIGNED_KEY_SCHEDULES(ctx, CONST)                     \
	((CONST struct aesni_key_schedules                          \
		*)((((uintptr_t)((CONST uint8_t *)&(                \
			AESNI_CTX(ctx).key_schedules.schedules))) + \
		       (AESNI_ALIGN - 1)) &                         \
	    (~(AESNI_ALIGN - 1))))

#define AESNI_ALIGNED_ENC_SCHEDULE(ctx, CONST) \
	(AESNI_ALIGNED_KEY_SCHEDULES(ctx, CONST)->enc_schedule)

#define AESNI_ALIGNED_DEC_SCHEDULE(ctx, CONST) \
	(AESNI_ALIGNED_KEY_SCHEDULES(ctx, CONST)->dec_schedule)

#define KKASSERT_AESNI_ALIGNED(ptr) \
	KKASSERT((((uintptr_t)(const uint8_t *)ptr) % AESNI_ALIGN) == 0)

static int
cipher_aesni_cbc_probe(const char *algo_name, const char *mode_name,
    int keysize_in_bits)
{
	if (aesni_disable)
		return (-1);

	if ((cpu_feature2 & CPUID2_AESNI) == 0)
		return (EINVAL);

	if ((strcmp(algo_name, "aes") == 0) &&
	    (strcmp(mode_name, "cbc") == 0) &&
	    (keysize_in_bits == 128 || keysize_in_bits == 192 ||
		keysize_in_bits == 256))
		return (0);

	return (-1);
}

static int
cipher_aesni_cbc_setkey(struct crypto_cipher_context *ctx,
    const uint8_t *keydata, int keylen_in_bytes)
{
	bzero(ctx, sizeof(*ctx));
	int rounds;

	switch (keylen_in_bytes * 8) {
	case 128:
		rounds = AES128_ROUNDS;
		break;
	case 192:
		rounds = AES192_ROUNDS;
		break;
	case 256:
		rounds = AES256_ROUNDS;
		break;
	default:
		return (EINVAL);
	}

	uint8_t *enc_schedule = AESNI_ALIGNED_ENC_SCHEDULE(ctx, );
	uint8_t *dec_schedule = AESNI_ALIGNED_DEC_SCHEDULE(ctx, );

	AESNI_CTX(ctx).rounds = rounds;

	aesni_set_enckey(keydata, enc_schedule, rounds);
	aesni_set_deckey(enc_schedule, dec_schedule, rounds);

	return (0);
}

static int
cipher_aesni_cbc_encrypt(const struct crypto_cipher_context *ctx,
    uint8_t *data, int datalen, struct crypto_cipher_iv *iv)
{
	if ((datalen % AES_BLOCK_LEN) != 0)
		return (EINVAL);

	const uint8_t *enc_schedule = AESNI_ALIGNED_ENC_SCHEDULE(ctx,
	    const);

	KKASSERT_AESNI_ALIGNED(enc_schedule);

	aesni_encrypt_cbc(AESNI_CTX(ctx).rounds, enc_schedule, datalen,
	    data, data, AESNI_IV(iv));

	return (0);
}

static int
cipher_aesni_cbc_decrypt(const struct crypto_cipher_context *ctx,
    uint8_t *data, int datalen, struct crypto_cipher_iv *iv)
{
	if ((datalen % AES_BLOCK_LEN) != 0)
		return (EINVAL);

	const uint8_t *dec_schedule = AESNI_ALIGNED_DEC_SCHEDULE(ctx,
	    const);

	KKASSERT_AESNI_ALIGNED(dec_schedule);

	aesni_decrypt_cbc(AESNI_CTX(ctx).rounds, dec_schedule, datalen,
	    data, AESNI_IV(iv));

	return (0);
}

const struct crypto_cipher cipher_aesni_cbc = {
	"aesni-cbc",
	"AES-CBC w/ CPU AESNI instruction",
	AES_BLOCK_LEN,
	AES_BLOCK_LEN,
	sizeof(aesni_ctx),
	cipher_aesni_cbc_probe,
	cipher_aesni_cbc_setkey,
	cipher_aesni_cbc_encrypt,
	cipher_aesni_cbc_decrypt,
};

#if 0
#define AES_XTS_BLOCKSIZE 16
#define AES_XTS_IVSIZE	  8
#define AES_XTS_ALPHA	  0x87 /* GF(2^128) generator polynomial */

static void
aesni_crypt_xts_block(int rounds, const void *key_schedule, uint8_t *tweak,
    const uint8_t *from, uint8_t *to, int do_encrypt)
{
	uint8_t block[AES_XTS_BLOCKSIZE];
	u_int i, carry_in, carry_out;

	for (i = 0; i < AES_XTS_BLOCKSIZE; i++)
		block[i] = from[i] ^ tweak[i];

	if (do_encrypt)
		aesni_enc(rounds - 1, key_schedule, block, to, NULL);
	else
		aesni_dec(rounds - 1, key_schedule, block, to, NULL);

	for (i = 0; i < AES_XTS_BLOCKSIZE; i++)
		to[i] ^= tweak[i];

	/* Exponentiate tweak. */
	carry_in = 0;
	for (i = 0; i < AES_XTS_BLOCKSIZE; i++) {
		carry_out = tweak[i] & 0x80;
		tweak[i] = (tweak[i] << 1) | (carry_in ? 1 : 0);
		carry_in = carry_out;
	}
	if (carry_in)
		tweak[0] ^= AES_XTS_ALPHA;
	bzero(block, sizeof(block));
}

static void
aesni_crypt_xts(int rounds, const void *data_schedule,
    const void *tweak_schedule, size_t len, const uint8_t *from, uint8_t *to,
    const uint8_t iv[AES_BLOCK_LEN], int do_encrypt)
{
	uint8_t tweak[AES_XTS_BLOCKSIZE];
	uint64_t blocknum;
	size_t i;

	/*
	 * Prepare tweak as E_k2(IV). IV is specified as LE representation
	 * of a 64-bit block number which we allow to be passed in directly.
	 */
	bcopy(iv, &blocknum, AES_XTS_IVSIZE);
	for (i = 0; i < AES_XTS_IVSIZE; i++) {
		tweak[i] = blocknum & 0xff;
		blocknum >>= 8;
	}
	/* Last 64 bits of IV are always zero. */
	bzero(tweak + AES_XTS_IVSIZE, AES_XTS_IVSIZE);
	aesni_enc(rounds - 1, tweak_schedule, tweak, tweak, NULL);

	len /= AES_XTS_BLOCKSIZE;
	for (i = 0; i < len; i++) {
		aesni_crypt_xts_block(rounds, data_schedule, tweak, from, to,
		    do_encrypt);
		from += AES_XTS_BLOCKSIZE;
		to += AES_XTS_BLOCKSIZE;
	}

	bzero(tweak, sizeof(tweak));
}

static void
aesni_encrypt_xts(int rounds, const void *data_schedule,
    const void *tweak_schedule, size_t len, const uint8_t *from, uint8_t *to,
    const uint8_t iv[AES_BLOCK_LEN])
{

	aesni_crypt_xts(rounds, data_schedule, tweak_schedule, len, from, to,
	    iv, 1);
}

static void
aesni_decrypt_xts(int rounds, const void *data_schedule,
    const void *tweak_schedule, size_t len, const uint8_t *from, uint8_t *to,
    const uint8_t iv[AES_BLOCK_LEN])
{

	aesni_crypt_xts(rounds, data_schedule, tweak_schedule, len, from, to,
	    iv, 0);
}
#endif

#if 0
static int
aesni_cipher_setup_common(struct aesni_session *ses, const uint8_t *key,
    int keylen)
{

	switch (ses->algo) {
	case CRYPTO_AES_CBC:
		switch (keylen) {
		case 128:
			ses->rounds = AES128_ROUNDS;
			break;
		case 192:
			ses->rounds = AES192_ROUNDS;
			break;
		case 256:
			ses->rounds = AES256_ROUNDS;
			break;
		default:
			return (EINVAL);
		}
		break;
	case CRYPTO_AES_XTS:
		switch (keylen) {
		case 256:
			ses->rounds = AES128_ROUNDS;
			break;
		case 512:
			ses->rounds = AES256_ROUNDS;
			break;
		default:
			return (EINVAL);
		}
		break;
	default:
		return (EINVAL);
	}

	aesni_set_enckey(key, ses->enc_schedule, ses->rounds);
	aesni_set_deckey(ses->enc_schedule, ses->dec_schedule, ses->rounds);
	if (ses->algo == CRYPTO_AES_CBC)
		karc4random_buf(ses->iv, sizeof(ses->iv));
	else /* if (ses->algo == CRYPTO_AES_XTS) */ {
		aesni_set_enckey(key + keylen / 16, ses->xts_schedule,
		    ses->rounds);
	}

	return (0);
}
#endif

#if 0
int
aesni_cipher_process(struct aesni_session *ses, struct cryptodesc *enccrd,
    struct cryptop *crp)
{
	uint8_t *buf = (uint8_t*)crp->crp_buf;
	int error = 0;

	if ((enccrd->crd_flags & CRD_F_ENCRYPT) != 0) {
		bcopy(enccrd->crd_iv, ses->iv, AES_BLOCK_LEN);
		if (ses->algo == CRYPTO_AES_CBC) {
			aesni_encrypt_cbc(ses->rounds, ses->enc_schedule,
			    enccrd->crd_len, buf, buf, ses->iv);
		} else /* if (ses->algo == CRYPTO_AES_XTS) */ {
			aesni_encrypt_xts(ses->rounds, ses->enc_schedule,
			    ses->xts_schedule, enccrd->crd_len, buf, buf,
			    ses->iv);
		}
	} else {
		bcopy(enccrd->crd_iv, ses->iv, AES_BLOCK_LEN);
		if (ses->algo == CRYPTO_AES_CBC) {
			aesni_decrypt_cbc(ses->rounds, ses->dec_schedule,
			    enccrd->crd_len, buf, ses->iv);
		} else /* if (ses->algo == CRYPTO_AES_XTS) */ {
			aesni_decrypt_xts(ses->rounds, ses->dec_schedule,
			    ses->xts_schedule, enccrd->crd_len, buf, buf,
			    ses->iv);
		}
	}
	if ((enccrd->crd_flags & CRD_F_ENCRYPT) != 0)
		bcopy(crp->crp_buf + (enccrd->crd_len - AES_BLOCK_LEN),
		    ses->iv, AES_BLOCK_LEN);

	return (error);
}
#endif
