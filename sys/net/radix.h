/*
 * Copyright (c) 1988, 1989, 1993
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
 *	@(#)radix.h	8.2 (Berkeley) 10/31/94
 * $FreeBSD: src/sys/net/radix.h,v 1.16.2.1 2000/05/03 19:17:11 wollman Exp $
 */

#ifndef _NET_RADIX_H_
#define	_NET_RADIX_H_

#include <sys/types.h>

/*
 * Radix search tree node layout.
 */

struct radix_node {
	struct	radix_mask *rn_mklist;	/* masks contained in subtree */
	struct	radix_node *rn_parent;	/* parent */
	int	rn_bit;		/* node: bit offset; leaf: -1-index(netmask) */
	u_char	rn_flags;	/* enumerated next */
#define RNF_NORMAL	1	/* leaf contains normal route */
#define RNF_ROOT	2	/* leaf is root node (embedded in the tree) */
#define RNF_ACTIVE	4	/* node is alive (for rtfree) */
	union {
		/* leaf-only data: */
		struct {
			/* object of search; point to the key passed by the
			 * caller */
			const u_char *rn_Key;
			/* optional netmask; if present, point to the rn_key
			 * of a node in the mask tree */
			const u_char *rn_Mask;
			/* chain of routes with the same key but different
			 * netmasks. */
			struct	radix_node *rn_Dupedkey;
		} rn_leaf;
		/* node-only data: */
		struct {
			int	rn_Offset;	/* where to start compare */
			u_char	rn_Bmask;	/* byte mask for bit test */
			struct	radix_node *rn_Left; /* progeny */
			struct	radix_node *rn_Right; /* progeny */
		} rn_node;
	}	rn_u;
#ifdef RN_DEBUG
	int rn_info;
	struct radix_node *rn_twin;
	struct radix_node *rn_ybro;
#endif
};

#define	rn_dupedkey	rn_u.rn_leaf.rn_Dupedkey
#define	rn_key		rn_u.rn_leaf.rn_Key
#define	rn_mask		rn_u.rn_leaf.rn_Mask
#define	rn_offset	rn_u.rn_node.rn_Offset
#define	rn_bmask	rn_u.rn_node.rn_Bmask
#define	rn_left		rn_u.rn_node.rn_Left
#define	rn_right	rn_u.rn_node.rn_Right

/*
 * We do this statically now because the dynamic initialization
 * occurs too late and has an ordering problem w/ pf preloads
 * vs protocol domains.
 */
#define RN_MAXKEYLEN	32
#define RN_MAXKEYONES	{ -1, -1, -1, -1, -1, -1, -1, -1,	\
			  -1, -1, -1, -1, -1, -1, -1, -1,	\
			  -1, -1, -1, -1, -1, -1, -1, -1,	\
			  -1, -1, -1, -1, -1, -1, -1, -1 }

/*
 * Annotations to tree concerning potential routes applying to subtrees.
 */

struct radix_mask {
	int	rm_bit;			/* bit offset; -1-index(netmask) */
	char	rm_unused;
	u_char	rm_flags;		/* cf. rn_flags */
	struct	radix_mask *rm_next;	/* list of more masks to try */
	union	{
		const u_char *rmu_mask;		/* the mask */
		struct	radix_node *rmu_leaf;	/* for normal routes */
	}	rm_rmu;
	int	rm_refs;		/* # of references to this struct */
};

#define	rm_mask rm_rmu.rmu_mask
#define	rm_leaf rm_rmu.rmu_leaf

typedef int walktree_f_t (struct radix_node *, void *);
typedef void freenode_f_t (struct radix_node *);

struct radix_node_head {
	struct	radix_node *rnh_treetop;

	/* add based on sockaddr */
	struct	radix_node *(*rnh_addaddr)
		    (const void *key, const void *mask,
		     struct radix_node_head *head, struct radix_node nodes[]);

	/* remove based on sockaddr */
	struct	radix_node *(*rnh_deladdr)
		    (const void *key, const void *mask,
		     struct radix_node_head *head);

	/* locate based on sockaddr */
	struct	radix_node *(*rnh_matchaddr)
		    (const void *key, struct radix_node_head *head);

	/* locate based on sockaddr */
	struct	radix_node *(*rnh_lookup)
		    (const void *key, const void *mask,
		     struct radix_node_head *head);

	/* traverse tree */
	int	(*rnh_walktree)
		    (struct radix_node_head *head, walktree_f_t *f, void *w);

	/* traverse tree below a */
	int	(*rnh_walktree_from)
		    (struct radix_node_head *head, const void *addr,
		     const void *mask, walktree_f_t *f, void *w);

	/*
	 * Do something when the last ref drops.
	 * A (*rnh_close)() routine
	 *	can clear RTF_UP
	 *	can remove a route from the radix tree
	 *	cannot change the reference count
	 *	cannot deallocate the route
	 */
	void	(*rnh_close)
		    (struct radix_node *rn, struct radix_node_head *head);

	/*
	 * Embedded nodes (flagged with RNF_ROOT) for an empty tree:
	 * - left node
	 * - top/root node (pointed by rnh_treetop)
	 * - right node
	 */
	struct	radix_node rnh_nodes[3];

	/* unused entries */
	int	rnh_addrsize;		/* permit, but not require fixed keys */
	int	rnh_pktsize;		/* permit, but not require fixed keys */
	struct	radix_node *(*rnh_addpkt)	/* add based on packet hdr */
		    (const void *v, const void *mask,
		     struct radix_node_head *head, struct radix_node nodes[]);
	struct	radix_node *(*rnh_delpkt)	/* remove based on packet hdr */
		    (const void *v, const void *mask,
		     struct radix_node_head *head);

	/* traverse tree starting from a */
	int	(*rnh_walktree_at)
		    (struct radix_node_head *head, const void *addr,
		     const void *mask, walktree_f_t *f, void *w);

	struct radix_node_head *rnh_maskhead;
};

#ifdef _KERNEL

#ifdef MALLOC_DECLARE
MALLOC_DECLARE(M_RTABLE);
#endif

#define R_Malloc(p, t, n) \
	(p = (t) kmalloc((n), M_RTABLE, M_INTWAIT | M_NULLOK))
#define R_Free(p)	kfree(p, M_RTABLE)

#else /* !_KERNEL */

#include <stdbool.h>

#define R_Malloc(p, t, n)	(p = (t) malloc((n)))
#define R_Free(p)		free(p)

#endif /* _KERNEL */

void			 rn_init(void);
int			 rn_inithead(struct radix_node_head **head,
				     struct radix_node_head *maskhead,
				     int off_bytes);
void			 rn_freehead(struct radix_node_head *head);
void			 rn_flush(struct radix_node_head *head,
				  freenode_f_t *f);
void			 rn_freemask(struct radix_node *rn);
struct radix_node_head	*rn_cpumaskhead(int cpu);
bool			 rn_refines(const void *m, const void *n);
struct radix_node	*rn_addmask(const void *mask, bool search, int skip,
				    struct radix_node_head *maskhead);
struct radix_node	*rn_addroute(const void *key, const void *mask,
				     struct radix_node_head *head,
				     struct radix_node nodes[2]);
struct radix_node	*rn_delete(const void *key, const void *mask,
				   struct radix_node_head *head);
struct radix_node	*rn_lookup(const void *key, const void *mask,
				   struct radix_node_head *head);
struct radix_node	*rn_match(const void *key,
				  struct radix_node_head *head);

#endif /* _NET_RADIX_H_ */
