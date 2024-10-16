/*-
 * The author of this code is Angelos D. Keromytis (angelos@cis.upenn.edu)
 * Copyright (c) 2002-2006 Sam Leffler, Errno Consulting
 *
 * This code was written by Angelos D. Keromytis in Athens, Greece, in
 * February 2000. Network Security Technologies Inc. (NSTI) kindly
 * supported the development of this code.
 *
 * Copyright (c) 2000, 2001 Angelos D. Keromytis
 *
 * SMP modifications by Matthew Dillon for the DragonFlyBSD Project
 *
 * Permission to use, copy, and modify this software with or without fee
 * is hereby granted, provided that this entire notice is included in
 * all source code copies of any software which is or includes a copy or
 * modification of this software.
 *
 * THIS SOFTWARE IS BEING PROVIDED "AS IS", WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTY. IN PARTICULAR, NONE OF THE AUTHORS MAKES ANY
 * REPRESENTATION OR WARRANTY OF ANY KIND CONCERNING THE
 * MERCHANTABILITY OF THIS SOFTWARE OR ITS FITNESS FOR ANY PARTICULAR
 * PURPOSE.
 *
 * $FreeBSD: src/sys/opencrypto/cryptosoft.c,v 1.23 2009/02/05 17:43:12 imp Exp $
 * $OpenBSD: cryptosoft.c,v 1.35 2002/04/26 08:43:50 deraadt Exp $
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/module.h>
#include <sys/sysctl.h>
#include <sys/errno.h>
#include <sys/endian.h>
#include <sys/random.h>
#include <sys/kernel.h>
#include <sys/uio.h>
#include <sys/spinlock2.h>

#include <crypto/blowfish/blowfish.h>
#include <crypto/sha1.h>
#include <crypto/cast/cast.h>
#include <crypto/skipjack/skipjack.h>
#include <sys/md5.h>

#include <opencrypto/cryptodev.h>
#include <opencrypto/cryptosoft.h>
#include <opencrypto/xform.h>

#include <sys/kobj.h>
#include <sys/bus.h>
#include "cryptodev_if.h"

static	int32_t swcr_id;
static	struct swcr_data **swcr_sessions = NULL;
static	u_int32_t swcr_sesnum;
static	u_int32_t swcr_minsesnum = 1;

static struct spinlock swcr_spin = SPINLOCK_INITIALIZER(swcr_spin, "swcr_spin");

static	int swcr_encdec(struct cryptodesc *, struct swcr_data *, caddr_t, int);
static	int swcr_freesession(device_t dev, u_int64_t tid);
static	int swcr_freesession_slot(struct swcr_data **swdp, u_int32_t sid);

/*
 * Apply a symmetric encryption/decryption algorithm.
 */
static int
swcr_encdec(struct cryptodesc *crd, struct swcr_data *sw, caddr_t buf,
    int flags)
{
	unsigned char iv[EALG_MAX_BLOCK_LEN];
	unsigned char *ivp;
	u_int8_t *kschedule;
	struct enc_xform *exf;
	int i, k, blks, ivlen;
	int error;

	exf = sw->sw_exf;
	blks = exf->blocksize;
	ivlen = exf->ivsize;

	/* Check for non-padded data */
	if (crd->crd_len % blks)
		return EINVAL;

	/* Initialize the IV */
	if (crd->crd_flags & CRD_F_ENCRYPT) {
		/* IV explicitly provided ? */
		if (crd->crd_flags & CRD_F_IV_EXPLICIT)
			bcopy(crd->crd_iv, iv, ivlen);
		else
			karc4random_buf(iv, ivlen);

		/* Do we need to write the IV */
		if (!(crd->crd_flags & CRD_F_IV_PRESENT))
			bcopy(iv, buf + crd->crd_inject, ivlen);

	} else {	/* Decryption */
			/* IV explicitly provided ? */
		if (crd->crd_flags & CRD_F_IV_EXPLICIT)
			bcopy(crd->crd_iv, iv, ivlen);
		else {
			/* Get IV off buf */
			bcopy(buf + crd->crd_inject, iv, ivlen);
		}
	}

	ivp = iv;

	spin_lock(&swcr_spin);
	kschedule = sw->sw_kschedule;
	++sw->sw_kschedule_refs;
	spin_unlock(&swcr_spin);

	/*
	 * xforms that provide a reinit method perform all IV
	 * handling themselves.
	 */
	if (exf->reinit)
		exf->reinit(kschedule, iv);

	{
		/*
		 * contiguous buffer
		 */
		if (exf->reinit) {
			for(i = 0; i < crd->crd_len; i += blks) {
				if (crd->crd_flags & CRD_F_ENCRYPT) {
					exf->encrypt(kschedule, buf + i, iv);
				} else {
					exf->decrypt(kschedule, buf + i, iv);
				}
			}
		} else if (crd->crd_flags & CRD_F_ENCRYPT) {
			for (i = 0; i < crd->crd_len; i += blks) {
				/* XOR with the IV/previous block, as appropriate. */
				if (i == 0)
					for (k = 0; k < blks; k++)
						buf[i + k] ^= ivp[k];
				else
					for (k = 0; k < blks; k++)
						buf[i + k] ^= buf[i + k - blks];
				exf->encrypt(kschedule, buf + i, iv);
			}
		} else {		/* Decrypt */
			/*
			 * Start at the end, so we don't need to keep the
			 * encrypted block as the IV for the next block.
			 */
			for (i = crd->crd_len - blks; i >= 0; i -= blks) {
				exf->decrypt(kschedule, buf + i, iv);

				/* XOR with the IV/previous block, as appropriate */
				if (i == 0)
					for (k = 0; k < blks; k++)
						buf[i + k] ^= ivp[k];
				else
					for (k = 0; k < blks; k++)
						buf[i + k] ^= buf[i + k - blks];
			}
		}
		error = 0; /* Done w/contiguous buffer encrypt/decrypt */
	}

	/*
	 * Cleanup - explicitly replace the session key if requested
	 *	     (horrible semantics for concurrent operation)
	 */
	spin_lock(&swcr_spin);
	--sw->sw_kschedule_refs;
	spin_unlock(&swcr_spin);

	return error;
}

/*
 * Generate a new software session.
 */
static int
swcr_newsession(device_t dev, u_int32_t *sid, struct cryptoini *cri)
{
	struct swcr_data *swd_base;
	struct swcr_data **swd;
	struct swcr_data **oswd;
	struct enc_xform *txf;
	u_int32_t i;
	u_int32_t n;
	int error;

	if (sid == NULL || cri == NULL)
		return EINVAL;

	swd_base = NULL;
	swd = &swd_base;

	while (cri) {
		*swd = kmalloc(sizeof(struct swcr_data),
			       M_CRYPTO_DATA, M_WAITOK | M_ZERO);

		switch (cri->cri_alg) {
		case CRYPTO_3DES_CBC:
			txf = &enc_xform_3des;
			goto enccommon;
		case CRYPTO_BLF_CBC:
			txf = &enc_xform_blf;
			goto enccommon;
		case CRYPTO_CAST_CBC:
			txf = &enc_xform_cast5;
			goto enccommon;
		case CRYPTO_SKIPJACK_CBC:
			txf = &enc_xform_skipjack;
			goto enccommon;
		case CRYPTO_RIJNDAEL128_CBC:
			txf = &enc_xform_rijndael128;
			goto enccommon;
		case CRYPTO_AES_XTS:
			txf = &enc_xform_aes_xts;
			goto enccommon;
		case CRYPTO_AES_CTR:
			txf = &enc_xform_aes_ctr;
			goto enccommon;
		case CRYPTO_CAMELLIA_CBC:
			txf = &enc_xform_camellia;
			goto enccommon;
		case CRYPTO_TWOFISH_CBC:
			txf = &enc_xform_twofish;
			goto enccommon;
		case CRYPTO_SERPENT_CBC:
			txf = &enc_xform_serpent;
			goto enccommon;
		case CRYPTO_TWOFISH_XTS:
			txf = &enc_xform_twofish_xts;
			goto enccommon;
		case CRYPTO_SERPENT_XTS:
			txf = &enc_xform_serpent_xts;
			goto enccommon;
		case CRYPTO_NULL_CBC:
			txf = &enc_xform_null;
			goto enccommon;
		enccommon:
			KKASSERT(txf->ctxsize > 0);
			(*swd)->sw_kschedule = kmalloc(txf->ctxsize,
						       M_CRYPTO_DATA,
						       M_WAITOK | M_ZERO);
			if (cri->cri_key != NULL) {
				error = txf->setkey((*swd)->sw_kschedule,
						    cri->cri_key,
						    cri->cri_klen / 8);
				if (error) {
					swcr_freesession_slot(&swd_base, 0);
					return error;
				}
			}
			(*swd)->sw_exf = txf;
			break;

		default:
			swcr_freesession_slot(&swd_base, 0);
			return EINVAL;
		}

		(*swd)->sw_alg = cri->cri_alg;
		cri = NULL;
		swd = &((*swd)->sw_next);
	}

	for (;;) {
		/*
		 * Atomically allocate a session
		 */
		spin_lock(&swcr_spin);
		for (i = swcr_minsesnum; i < swcr_sesnum; ++i) {
			if (swcr_sessions[i] == NULL)
				break;
		}
		if (i < swcr_sesnum) {
			swcr_sessions[i] = swd_base;
			swcr_minsesnum = i + 1;
			spin_unlock(&swcr_spin);
			break;
		}
		n = swcr_sesnum;
		spin_unlock(&swcr_spin);

		/*
		 * A larger allocation is required, reallocate the array
		 * and replace, checking for SMP races.
		 */
		if (n < CRYPTO_SW_SESSIONS)
			n = CRYPTO_SW_SESSIONS;
		else
			n = n * 3 / 2;
		swd = kmalloc(n * sizeof(struct swcr_data *),
			      M_CRYPTO_DATA, M_WAITOK | M_ZERO);

		spin_lock(&swcr_spin);
		if (swcr_sesnum >= n) {
			spin_unlock(&swcr_spin);
			kfree(swd, M_CRYPTO_DATA);
		} else if (swcr_sesnum) {
			bcopy(swcr_sessions, swd,
			      swcr_sesnum * sizeof(struct swcr_data *));
			oswd = swcr_sessions;
			swcr_sessions = swd;
			swcr_sesnum = n;
			spin_unlock(&swcr_spin);
			kfree(oswd, M_CRYPTO_DATA);
		} else {
			swcr_sessions = swd;
			swcr_sesnum = n;
			spin_unlock(&swcr_spin);
		}
	}

	*sid = i;
	return 0;
}

/*
 * Free a session.
 */
static int
swcr_freesession(device_t dev, u_int64_t tid)
{
	u_int32_t sid = CRYPTO_SESID2LID(tid);

	if (sid > swcr_sesnum || swcr_sessions == NULL ||
	    swcr_sessions[sid] == NULL) {
		return EINVAL;
	}

	/* Silently accept and return */
	if (sid == 0)
		return 0;

	return(swcr_freesession_slot(&swcr_sessions[sid], sid));
}

static
int
swcr_freesession_slot(struct swcr_data **swdp, u_int32_t sid)
{
	struct enc_xform *txf;
	struct swcr_data *swd;
	struct swcr_data *swnext;

	/*
	 * Protect session detachment with the spinlock.
	 */
	spin_lock(&swcr_spin);
	swnext = *swdp;
	*swdp = NULL;
	if (sid && swcr_minsesnum > sid)
		swcr_minsesnum = sid;
	spin_unlock(&swcr_spin);

	/*
	 * Clean up at our leisure.
	 */
	while ((swd = swnext) != NULL) {
		swnext = swd->sw_next;

		swd->sw_next = NULL;

		switch (swd->sw_alg) {
		case CRYPTO_DES_CBC:
		case CRYPTO_3DES_CBC:
		case CRYPTO_BLF_CBC:
		case CRYPTO_CAST_CBC:
		case CRYPTO_SKIPJACK_CBC:
		case CRYPTO_RIJNDAEL128_CBC:
		case CRYPTO_AES_XTS:
		case CRYPTO_AES_CTR:
		case CRYPTO_CAMELLIA_CBC:
		case CRYPTO_TWOFISH_CBC:
		case CRYPTO_SERPENT_CBC:
		case CRYPTO_TWOFISH_XTS:
		case CRYPTO_SERPENT_XTS:
		case CRYPTO_NULL_CBC:
			txf = swd->sw_exf;

			if (swd->sw_kschedule) {
				explicit_bzero(swd->sw_kschedule, txf->ctxsize);
				kfree(swd->sw_kschedule, M_CRYPTO_DATA);
			}
			break;
		}

		//FREE(swd, M_CRYPTO_DATA);
		kfree(swd, M_CRYPTO_DATA);
	}
	return 0;
}

/*
 * Process a software request.
 */
static int
swcr_process(device_t dev, struct cryptop *crp, int hint)
{
	struct cryptodesc *crd;
	struct swcr_data *sw;
	u_int32_t lid;

	/* Sanity check */
	if (crp == NULL)
		return EINVAL;

	if (crp->crp_desc == NULL || crp->crp_buf == NULL) {
		crp->crp_etype = EINVAL;
		goto done;
	}

	lid = crp->crp_sid & 0xffffffff;
	if (lid >= swcr_sesnum || lid == 0 || swcr_sessions[lid] == NULL) {
		crp->crp_etype = ENOENT;
		goto done;
	}

	/* Go through crypto descriptors, processing as we go */
	if ((crd = crp->crp_desc) != NULL) {
		/*
		 * Find the crypto context.
		 *
		 * XXX Note that the logic here prevents us from having
		 * XXX the same algorithm multiple times in a session
		 * XXX (or rather, we can but it won't give us the right
		 * XXX results). To do that, we'd need some way of differentiating
		 * XXX between the various instances of an algorithm (so we can
		 * XXX locate the correct crypto context).
		 */
		for (sw = swcr_sessions[lid];
		    sw && sw->sw_alg != crd->crd_alg;
		    sw = sw->sw_next)
			;

		/* No such context ? */
		if (sw == NULL) {
			crp->crp_etype = EINVAL;
			goto done;
		}
		switch (sw->sw_alg) {
		case CRYPTO_DES_CBC:
		case CRYPTO_3DES_CBC:
		case CRYPTO_BLF_CBC:
		case CRYPTO_CAST_CBC:
		case CRYPTO_SKIPJACK_CBC:
		case CRYPTO_RIJNDAEL128_CBC:
		case CRYPTO_AES_XTS:
		case CRYPTO_AES_CTR:
		case CRYPTO_CAMELLIA_CBC:
		case CRYPTO_TWOFISH_CBC:
		case CRYPTO_SERPENT_CBC:
		case CRYPTO_TWOFISH_XTS:
		case CRYPTO_SERPENT_XTS:
			if ((crp->crp_etype = swcr_encdec(crd, sw,
			    crp->crp_buf, crp->crp_flags)) != 0)
				goto done;
			break;
		case CRYPTO_NULL_CBC:
			crp->crp_etype = 0;
			break;

		default:
			/* Unknown/unsupported algorithm */
			crp->crp_etype = EINVAL;
			goto done;
		}
	}

done:
	crypto_done(crp);
	lwkt_yield();
	return 0;
}

static void
swcr_identify(driver_t *drv, device_t parent)
{
	/* NB: order 10 is so we get attached after h/w devices */
	/* XXX: wouldn't bet about this BUS_ADD_CHILD correctness */
	if (device_find_child(parent, "cryptosoft", -1) == NULL &&
	    BUS_ADD_CHILD(parent, parent, 10, "cryptosoft", -1) == 0)
		panic("cryptosoft: could not attach");
}

static int
swcr_probe(device_t dev)
{
	device_set_desc(dev, "software crypto");
	return (0);
}

static int
swcr_attach(device_t dev)
{
	swcr_id = crypto_get_driverid(dev, CRYPTOCAP_F_SOFTWARE |
					   CRYPTOCAP_F_SYNC |
					   CRYPTOCAP_F_SMP);
	if (swcr_id < 0) {
		device_printf(dev, "cannot initialize!");
		return ENOMEM;
	}
#define	REGISTER(alg) \
	crypto_register(swcr_id, alg, 0,0)
	REGISTER(CRYPTO_DES_CBC);
	REGISTER(CRYPTO_3DES_CBC);
	REGISTER(CRYPTO_BLF_CBC);
	REGISTER(CRYPTO_CAST_CBC);
	REGISTER(CRYPTO_SKIPJACK_CBC);
	REGISTER(CRYPTO_NULL_CBC);
	REGISTER(CRYPTO_RIJNDAEL128_CBC);
	REGISTER(CRYPTO_AES_XTS);
	REGISTER(CRYPTO_AES_CTR);
	REGISTER(CRYPTO_CAMELLIA_CBC);
	REGISTER(CRYPTO_TWOFISH_CBC);
	REGISTER(CRYPTO_SERPENT_CBC);
	REGISTER(CRYPTO_TWOFISH_XTS);
	REGISTER(CRYPTO_SERPENT_XTS);
#undef REGISTER

	return 0;
}

static int
swcr_detach(device_t dev)
{
	crypto_unregister_all(swcr_id);
	if (swcr_sessions != NULL)
		kfree(swcr_sessions, M_CRYPTO_DATA);
	return 0;
}

static device_method_t swcr_methods[] = {
	DEVMETHOD(device_identify,	swcr_identify),
	DEVMETHOD(device_probe,		swcr_probe),
	DEVMETHOD(device_attach,	swcr_attach),
	DEVMETHOD(device_detach,	swcr_detach),

	DEVMETHOD(cryptodev_newsession,	swcr_newsession),
	DEVMETHOD(cryptodev_freesession,swcr_freesession),
	DEVMETHOD(cryptodev_process,	swcr_process),

	DEVMETHOD_END
};

static driver_t swcr_driver = {
	"cryptosoft",
	swcr_methods,
	0,		/* NB: no softc */
};
static devclass_t swcr_devclass;

/*
 * NB: We explicitly reference the crypto module so we
 * get the necessary ordering when built as a loadable
 * module.  This is required because we bundle the crypto
 * module code together with the cryptosoft driver (otherwise
 * normal module dependencies would handle things).
 */
extern int crypto_modevent(struct module *, int, void *);
/* XXX where to attach */
DRIVER_MODULE(cryptosoft, nexus, swcr_driver, swcr_devclass, crypto_modevent,NULL);
MODULE_VERSION(cryptosoft, 1);
MODULE_DEPEND(cryptosoft, crypto, 1, 1, 1);
