# $FreeBSD: src/sys/modules/crypto/Makefile,v 1.6 2007/05/09 19:37:01 gnn Exp $

KMOD=	crypto

.PATH:	${.CURDIR}
SRCS+=	crypto_mod.c crypto_cipher.c

SRCS+=	sha1.c
SRCS+=	chachapoly.c

.PATH:	${.CURDIR}/blake2
SRCS+=	blake2s.c

.PATH:	${.CURDIR}/chacha20
SRCS+=	chacha.c

.PATH:	${.CURDIR}/curve25519
SRCS+=	curve25519.c

# required by: smb_crypt
.PATH:	${.CURDIR}/des
SRCS+=	des_ecb.c des_enc.c des_setkey.c

.PATH:	${.CURDIR}/poly1305
SRCS+=	poly1305.c

.PATH:	${.CURDIR}/rijndael
SRCS+=	rijndael-alg-fst.c rijndael-api.c

.PATH:	${.CURDIR}/rmd160
SRCS+=	rmd160.c

.PATH:	${.CURDIR}/sha2
SRCS+=	sha2.c

.PATH:	${.CURDIR}/siphash
SRCS+=	siphash.c

.PATH:	${.CURDIR}/aesni
SRCS+=	aesni.c
SRCS+=	aesencdec_${MACHINE_ARCH}.S
SRCS+=	aeskeys_${MACHINE_ARCH}.S

# required by: netgraph
SUBDIR=	rc4

.include <bsd.kmod.mk>
