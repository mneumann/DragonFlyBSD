/*
 * Copyright (c) 1982, 1986, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)un.h	8.3 (Berkeley) 2/19/95
 * $FreeBSD: src/sys/sys/un.h,v 1.17.2.1 2002/03/09 05:22:23 dd Exp $
 */

#ifndef _SYS_UN_H_
#define	_SYS_UN_H_

#include <machine/stdint.h>

#ifndef _SA_FAMILY_T_DECLARED
typedef	__uint8_t	sa_family_t;
#define	_SA_FAMILY_T_DECLARED
#endif

/*
 * Definitions for UNIX IPC domain.
 */
struct sockaddr_un {
	__uint8_t	sun_len;	/* sockaddr len including null */
	sa_family_t	sun_family;	/* AF_UNIX */
	char		sun_path[104];	/* path name (gag) */
};

#if __BSD_VISIBLE
/* Socket options. */
#define	LOCAL_PEERCRED		0x001		/* retrieve peer credentials */
#endif

#ifdef _KERNEL
struct mbuf;
struct socket;
union netmsg;

int	uipc_usrreq(struct socket *so, int req, struct mbuf *m,
	    struct mbuf *nam, struct mbuf *control);
void	uipc_ctloutput(union netmsg *msg);
int	unp_connect2(struct socket *so, struct socket *so2, struct ucred *cred);
void	unp_dispose(struct mbuf *m);
int	unp_externalize(struct mbuf *rights, int flags);
void	unp_init(void);
extern	struct pr_usrreqs uipc_usrreqs;
#else /* !_KERNEL */

#if __BSD_VISIBLE
/* actual length of an initialized sockaddr_un */
#define	SUN_LEN(su) \
	(sizeof(*(su)) - sizeof((su)->sun_path) + strlen((su)->sun_path))
#endif

#endif /* _KERNEL */

#endif /* !_SYS_UN_H_ */
