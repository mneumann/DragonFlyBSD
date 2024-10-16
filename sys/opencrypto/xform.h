/*	$FreeBSD: src/sys/opencrypto/xform.h,v 1.4 2007/05/09 19:37:02 gnn Exp $	*/
/*	$OpenBSD: xform.h,v 1.8 2001/08/28 12:20:43 ben Exp $	*/

/*-
 * The author of this code is Angelos D. Keromytis (angelos@cis.upenn.edu)
 *
 * This code was written by Angelos D. Keromytis in Athens, Greece, in
 * February 2000. Network Security Technologies Inc. (NSTI) kindly
 * supported the development of this code.
 *
 * Copyright (c) 2000 Angelos D. Keromytis
 *
 * Permission to use, copy, and modify this software without fee
 * is hereby granted, provided that this entire notice is included in
 * all source code copies of any software which is or includes a copy or
 * modification of this software.
 *
 * THIS SOFTWARE IS BEING PROVIDED "AS IS", WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTY. IN PARTICULAR, NONE OF THE AUTHORS MAKES ANY
 * REPRESENTATION OR WARRANTY OF ANY KIND CONCERNING THE
 * MERCHANTABILITY OF THIS SOFTWARE OR ITS FITNESS FOR ANY PARTICULAR
 * PURPOSE.
 */

#ifndef _CRYPTO_XFORM_H_
#define _CRYPTO_XFORM_H_

struct enc_xform {
	int type;
	char *name;
	u_int16_t blocksize;
	u_int16_t ivsize;
	u_int16_t minkey;
	u_int16_t maxkey;
	u_int16_t ctxsize;
	void (*encrypt) (caddr_t, u_int8_t *, u_int8_t *);
	void (*decrypt) (caddr_t, u_int8_t *, u_int8_t *);
	int (*setkey) (void *, u_int8_t *, int);
	void (*reinit) (caddr_t, u_int8_t *);
};

extern struct enc_xform enc_xform_null;
extern struct enc_xform enc_xform_3des;
extern struct enc_xform enc_xform_blf;
extern struct enc_xform enc_xform_cast5;
extern struct enc_xform enc_xform_skipjack;
extern struct enc_xform enc_xform_rijndael128;
extern struct enc_xform enc_xform_aes_xts;
extern struct enc_xform enc_xform_aes_ctr;
extern struct enc_xform enc_xform_aes_gmac;
extern struct enc_xform enc_xform_arc4;
extern struct enc_xform enc_xform_camellia;
extern struct enc_xform enc_xform_twofish;
extern struct enc_xform enc_xform_serpent;
extern struct enc_xform enc_xform_twofish_xts;
extern struct enc_xform enc_xform_serpent_xts;

#ifdef MALLOC_DECLARE
MALLOC_DECLARE(M_XDATA);
#endif
#endif /* _CRYPTO_XFORM_H_ */
