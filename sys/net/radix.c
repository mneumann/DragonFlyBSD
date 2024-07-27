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
 *	@(#)radix.c	8.4 (Berkeley) 11/2/94
 * $FreeBSD: src/sys/net/radix.c,v 1.20.2.3 2002/04/28 05:40:25 suz Exp $
 */

/*
 * Routines to build and maintain radix trees for routing lookups.
 */

#include <sys/param.h>
#ifdef	_KERNEL
#include <sys/systm.h>
#include <sys/domain.h>
#include <sys/globaldata.h>
#include <sys/malloc.h>
#include <sys/queue.h>
#include <sys/syslog.h>
#include <sys/thread.h>
#include <net/netisr2.h>
#include <net/netmsg2.h>
#else
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <syslog.h>
#endif
#include <net/radix.h>

#ifndef _KERNEL
#undef MAXCPU
#define MAXCPU			1
#define mycpuid			0
#define log(l, ...)		syslog(l, __VA_ARGS__)
#define kprintf(fmt, ...)	printf(fmt, ##__VA_ARGS__)
#define print_backtrace(...)	/* nothing */
#define panic(fmt, ...) \
	do { \
		fprintf(stderr, "PANIC: " fmt "\n", ##__VA_ARGS__); \
		abort(); \
	} while (0)
#endif

/*
 * The arguments to the radix functions are really counted byte arrays with
 * the length in the first byte.  struct sockaddr's fit this type structurally.
 * Cast the result to int as this is the dominant usage.
 */
#define clen(c)	(int)(*(const u_char *)(c))


static struct radix_mask *rn_mkfreelist[MAXCPU];
static struct radix_node_head *mask_rnheads[MAXCPU];

static const u_char rn_zeros[RN_MAXKEYLEN];
static const u_char rn_ones[RN_MAXKEYLEN] = RN_MAXKEYONES;

#ifdef RN_DEBUG
static int rn_nodenum;
static struct radix_node *rn_clist;
static bool rn_debug = true;
#endif


static __inline struct radix_mask *
MKGet(struct radix_mask **l)
{
	struct radix_mask *m;

	if (*l != NULL) {
		m = *l;
		*l = m->rm_next;
	} else {
		R_Malloc(m, struct radix_mask *, sizeof(*m));
	}
	return m;
}

static __inline void
MKFree(struct radix_mask **l, struct radix_mask *m)
{
	m->rm_next = *l;
	*l = m;
}

/*
 * The data structure for the keys is a radix tree with one way
 * branching removed.  The index rn_bit at an internal node n represents a bit
 * position to be tested.  The tree is arranged so that all descendants
 * of a node n have keys whose bits all agree up to position rn_bit - 1.
 * (We say the index of n is rn_bit.)
 *
 * There is at least one descendant which has a one bit at position rn_bit,
 * and at least one with a zero there.
 *
 * A route is determined by a pair of key and mask.  We require that the
 * bit-wise logical and of the key and mask to be the key.
 * We define the index of a route associated with the mask to be
 * the first bit number in the mask where 0 occurs (with bit number 0
 * representing the highest order bit).
 *
 * We say a mask is normal if every bit is 0, past the index of the mask.
 * If a node n has a descendant (k, m) with index(m) == index(n) == rn_bit,
 * and m is a normal mask, then the route applies to every descendant of n.
 * If the index(m) < rn_bit, this implies the trailing last few bits of k
 * before bit rn_bit are all 0, (and hence consequently true of every
 * descendant of n), so the route applies to all descendants of the node
 * as well.
 *
 * Similar logic shows that a non-normal mask m such that
 * index(m) <= index(n) could potentially apply to many children of n.
 * Thus, for each non-host route, we attach its mask to a list at an internal
 * node as high in the tree as we can go.
 *
 * The present version of the code makes use of normal routes in short-
 * circuiting an explicit mask and compare operation when testing whether
 * a key satisfies a normal route, and also in remembering the unique leaf
 * that governs a subtree.
 */

/*
 * Search key <key> in the subtree from <head> until encountering
 * a leaf node and return it.
 *
 * NOTE: Will never return NULL because the embedded default root node.
 */
static struct radix_node *
rn_search(const void *_key, struct radix_node *head)
{
	struct radix_node *x;
	const u_char *key;

	key = _key;
	x = head;
	while (x->rn_bit >= 0) {
		if (x->rn_bmask & key[x->rn_offset])
			x = x->rn_right;
		else
			x = x->rn_left;
	}
	return (x);
}

/*
 * Similar to rn_search() but with the netmask <mask> applied.
 *
 * NOTE: The netmask can be the all-zero default mask.
 */
static struct radix_node *
rn_search_m(const void *_key, const void *_mask, struct radix_node *head)
{
	struct radix_node *x;
	const u_char *key, *mask;

	key = _key;
	mask = _mask;
	x = head;
	while (x->rn_bit >= 0) {
		if ((x->rn_bmask & mask[x->rn_offset]) &&
		    (x->rn_bmask & key[x->rn_offset]))
			x = x->rn_right;
		else
			x = x->rn_left;
	}
	return (x);
}

/*
 * Compare the two netmasks and return true if netmask <m> is strictly more
 * specific than netmask <n>.
 *
 * NOTE: Non-contiguous netmask is supported.
 */
bool
rn_refines(const void *_m, const void *_n)
{
	const u_char *m, *n, *lim, *lim2;
	int longer;
	bool equal;

	m = _m;
	n = _n;
	lim2 = lim = n + clen(n);
	longer = clen(n++) - clen(m++);
	if (longer > 0)
		lim -= longer;

	equal = true;
	while (n < lim) {
		if (*n & ~(*m))
			return (false);
		if (*n++ != *m++)
			equal = false;
	}
	while (n < lim2) {
		if (*n++) /* n is longer and more specific */
			return (false);
	}
	if (equal && (longer < 0)) {
		lim2 = m - longer;
		while (m < lim2) {
			if (*m++) /* m is longer and more specific */
				return (true);
		}
	}

	return (!equal);
}

/*
 * Lookup the longest-prefix match of the key <key> in the tree <head>.
 * The netmask <mask> can be NULL; if specified, the result must have the
 * same mask, or NULL is returned.
 */
struct radix_node *
rn_lookup(const void *_key, const void *_mask, struct radix_node_head *head)
{
	struct radix_node *x;
	const u_char *key, *mask, *netmask;

	key = _key;
	mask = _mask;
	netmask = NULL;

	if (mask != NULL) {
		x = rn_addmask(mask, true, head->rnh_treetop->rn_offset,
			       head->rnh_maskhead);
		if (x == NULL) /* mask doesn't exist in the mask tree */
			return (NULL);
		netmask = x->rn_key;
	}

	x = rn_match(key, head);
	if (x != NULL && netmask != NULL) {
		/* check the duped-key chain for different masks */
		while (x != NULL && x->rn_mask != netmask)
			x = x->rn_dupedkey;
	}

	return (x);
}

/*
 * Check whether the key <key> matches the (key, mask) of the given
 * radix node <leaf>.  The <skip> parameter gives the number of bytes
 * to skip for the keys and mask.
 */
static bool
rn_satisfies_leaf(const void *key, struct radix_node *leaf, int skip)
{
	const u_char *cp, *cp2, *cp3, *cplim;
	int length;

	cp = key;
	cp2 = leaf->rn_key;
	cp3 = leaf->rn_mask;

	length = MIN(clen(cp), clen(cp2));
	if (cp3 == NULL)
		cp3 = rn_ones;
	else
		length = MIN(length, clen(cp3));

	cplim = cp + length;
	cp2 += skip;
	cp3 += skip;
	for (cp += skip; cp < cplim; cp++, cp2++, cp3++) {
		if ((*cp ^ *cp2) & *cp3)
			return (false);
	}

	return (true);
}


/*
 * Search for the longest-prefix match of the key <key>.
 */
struct radix_node *
rn_match(const void *key, struct radix_node_head *head)
{
	struct radix_node *top, *t, *saved_t;
	const u_char *cp, *cp2, *cplim;
	int klen, matched_off, test, bit, rn_bit;

	top = head->rnh_treetop;

	t = rn_search(key, top);
	/*
	 * See if we match exactly as a host destination, or at least learn
	 * how many bits match, for normal mask finesse.
	 *
	 * It doesn't hurt to limit how many bytes to check to the length of
	 * the mask, since if it matches we had a genuine match and the leaf
	 * we have is the most specific one anyway; if it didn't match with
	 * a shorter length it would fail with a long one.  This wins big
	 * for class B&C netmasks which are probably the most common case...
	 */
	if (t->rn_mask != NULL)
		klen = clen(t->rn_mask);
	else
		klen = clen(key);
	cplim = (const u_char *)key + klen;
	cp = (const u_char *)key + top->rn_offset;
	cp2 = t->rn_key + top->rn_offset;
	for (; cp < cplim; cp++, cp2++) {
		if (*cp != *cp2)
			goto on1;
	}

	/*
	 * This extra grot is in case we are explicitly asked
	 * to look up the default (i.e., all-zero address).  Ugh!
	 *
	 * Never return the root node itself, it seems to cause a
	 * lot of confusion.
	 */
	if (t->rn_flags & RNF_ROOT)
		t = t->rn_dupedkey;
	return (t);

on1:
	/* Find the first bit that differs. */
	test = (*cp ^ *cp2) & 0xff;
	for (bit = 7; (test >>= 1) > 0;)
		bit--;
	matched_off = cp - (const u_char *)key;
	bit += matched_off << 3;
	rn_bit = -1 - bit;

	/*
	 * Even if we don't match exactly as a host, we may match if the leaf
	 * we wound up at has routes to networks.  Check those routes.
	 */
	saved_t = t;
	/* Skip the host route, which might only appear at the first. */
	if (t->rn_mask == NULL)
		t = t->rn_dupedkey;
	for (; t != NULL; t = t->rn_dupedkey) {
		if (t->rn_flags & RNF_NORMAL) {
			if (rn_bit <= t->rn_bit)
				return (t);
		} else if (rn_satisfies_leaf(key, t, matched_off))
			return (t);
	}
	t = saved_t;

	/*
	 * Start searching up the tree for network routes.
	 */
	do {
		struct radix_node *x;
		struct radix_mask *m;
		int skip;

		t = t->rn_parent;
		/*
		 * If non-contiguous masks ever become important
		 * we can restore the masking and open coding of
		 * the search and satisfaction test and put the
		 * calculation of "skip" back before the "do".
		 */
		for (m = t->rn_mklist; m != NULL; m = m->rm_next) {
			if (m->rm_flags & RNF_NORMAL) {
				if (rn_bit <= m->rm_bit)
					return (m->rm_leaf);
			} else {
				skip = MIN(t->rn_offset, matched_off);
				x = rn_search_m(key, m->rm_mask, t);
				while (x != NULL && x->rn_mask != m->rm_mask)
					x = x->rn_dupedkey;
				if (x != NULL &&
				    rn_satisfies_leaf(key, x, skip))
					return (x);
			}
		}
	} while (t != top);

	return (NULL);
}

/*
 * Whenever to add a new leaf to the tree, another parent node is needed.
 * So they are allocated as an array of two elements: the first element is
 * the leaf, the second one is the parent node.
 *
 * This function initializes the given pair of nodes <nodes>, so that the
 * leaf is the left child of the parent node.
 */
static struct radix_node *
rn_newpair(const void *key, int bit, struct radix_node nodes[2])
{
	struct radix_node *left, *parent;

	left = &nodes[0];
	parent = &nodes[1];

	parent->rn_bit = bit;
	parent->rn_bmask = 0x80 >> (bit & 0x7);
	parent->rn_offset = bit >> 3;
	parent->rn_left = left;
	parent->rn_flags = RNF_ACTIVE;
	parent->rn_mklist = NULL;

	left->rn_bit = -1;
	left->rn_key = key;
	left->rn_parent = parent;
	left->rn_flags = parent->rn_flags;
	left->rn_mklist = NULL;

#ifdef RN_DEBUG
	left->rn_info = rn_nodenum++;
	parent->rn_info = rn_nodenum++;
	left->rn_twin = parent;
	left->rn_ybro = rn_clist;
	rn_clist = left;
#endif

	return (parent);
}

/*
 * Insert the key <key> to the radix tree <head>.
 *
 * If the key already exists, then set <dupentry> to 'true' and return the
 * node of the existing duped key.  Otherwise, set <dupentry> to 'false',
 * insert the key to the tree by making use of the given nodes <nodes>, and
 * return the node of the inserted key (i.e., &nodes[0]).
 */
static struct radix_node *
rn_insert(const void *key, struct radix_node_head *head, bool *dupentry,
	  struct radix_node nodes[2])
{
	struct radix_node *top, *t, *tt;
	const u_char *cp;
	unsigned int bit;
	int head_off, klen;

	top = head->rnh_treetop;
	head_off = top->rn_offset;
	klen = clen(key);
	cp = (const u_char *)key + head_off;
	t = rn_search(key, top);

	/*
	 * Find the first bit where the key and t->rn_key differ.
	 */
    {
	const u_char *cp2 = t->rn_key + head_off;
	const u_char *cplim = (const u_char *)key + klen;
	int cmp_res;

	while (cp < cplim) {
		if (*cp2++ != *cp++)
			goto on1;
	}

	*dupentry = true;
	return (t);

on1:
	*dupentry = false;
	cmp_res = (cp[-1] ^ cp2[-1]) & 0xff;
	for (bit = (cp - (const u_char *)key) << 3; cmp_res; bit--)
		cmp_res >>= 1;
    }
    {
	struct radix_node *p, *x = top;

	cp = key;
	do {
		p = x;
		if (cp[x->rn_offset] & x->rn_bmask)
			x = x->rn_right;
		else
			x = x->rn_left;
	} while (bit > (unsigned int)x->rn_bit);
		/* shortcut of: x->rn_bit < bit && x->rn_bit >= 0 */
#ifdef RN_DEBUG
	if (rn_debug) {
		log(LOG_DEBUG, "%s: Going In:\n", __func__);
		traverse(p);
	}
#endif
	t = rn_newpair(key, bit, nodes);
	tt = t->rn_left;
	if ((cp[p->rn_offset] & p->rn_bmask) == 0)
		p->rn_left = t;
	else
		p->rn_right = t;
	x->rn_parent = t;
	t->rn_parent = p; /* frees x, p as temp vars below */
	if ((cp[t->rn_offset] & t->rn_bmask) == 0) {
		t->rn_right = x;
	} else {
		t->rn_right = tt;
		t->rn_left = x;
	}
#ifdef RN_DEBUG
	if (rn_debug) {
		log(LOG_DEBUG, "%s: Coming Out:\n", __func__);
		traverse(p);
	}
#endif
    }
	return (tt);
}

/*
 * Add the netmask <mask> to the mask tree <maskhead>.  If <search> is
 * 'true', then only check the existence of the given mask but don't
 * actually add it.
 *
 * The <skip> parameter specifies the number of bytes to skip in <mask>
 * to obtain the mask data.  (NOTE: The length of a mask key doesn't
 * count the trailing zero bytes.)
 *
 * Return a pointer to the mask node on success; otherwise NULL on error.
 */
struct radix_node *
rn_addmask(const void *_mask, bool search, int skip,
	   struct radix_node_head *maskhead)
{
	struct radix_node *x, *saved_x;
	const u_char *mask, *cp, *cplim;
	u_char *p, addmask_key[RN_MAXKEYLEN];
	int bit, mlen;
	bool maskduplicated, isnormal;

	mask = _mask;
	if ((mlen = clen(mask)) > RN_MAXKEYLEN)
		mlen = RN_MAXKEYLEN;
	if (skip == 0)
		skip = 1;
	if (mlen <= skip)
		return (maskhead->rnh_nodes); /* all-zero key */

	bzero(addmask_key, sizeof(addmask_key));
	if (skip > 1)
		bcopy(rn_ones + 1, addmask_key + 1, skip - 1);
	bcopy(mask + skip, addmask_key + skip, mlen - skip);
	/* Trim trailing zeroes. */
	for (cp = addmask_key + mlen; (cp > addmask_key) && cp[-1] == 0;)
		cp--;
	mlen = cp - addmask_key;
	if (mlen <= skip)
		return (maskhead->rnh_nodes); /* all-zero key */

	*addmask_key = mlen;
	x = rn_search(addmask_key, maskhead->rnh_treetop);
	if (x->rn_key == NULL) {
		kprintf("WARNING: radix_node->rn_key is NULL rn=%p\n", x);
		print_backtrace(-1);
		x = NULL;
	} else if (bcmp(addmask_key, x->rn_key, mlen) != 0) {
		x = NULL;
	}
	if (x != NULL || search)
		return (x);

	R_Malloc(x, struct radix_node *, RN_MAXKEYLEN + 2 * (sizeof *x));
	if ((saved_x = x) == NULL)
		return (NULL);

	bzero(x, RN_MAXKEYLEN + 2 * (sizeof *x));
	mask = p = (u_char *)(x + 2);
	bcopy(addmask_key, p, mlen);
	x = rn_insert(mask, maskhead, &maskduplicated, x);
	if (maskduplicated) {
		log(LOG_ERR, "%s: mask impossibly already in tree", __func__);
		R_Free(saved_x);
		return (x);
	}

	/*
	 * Calculate the index of mask, and check for normalcy.
	 *
	 * First find the first byte with a 0 bit, then if there are more
	 * bits left (remember we already trimmed the trailing zeros),
	 * the pattern must be one of those in normal_chars[], or we have
	 * a non-contiguous mask.
	 */
	bit = 0;
	isnormal = true;
	cplim = mask + mlen;
	for (cp = mask + skip; cp < cplim; cp++) {
		if (*cp != 0xff)
			break;
	}
	if (cp != cplim) {
		static const u_char normal_chars[] = {
			0, 0x80, 0xc0, 0xe0, 0xf0, 0xf8, 0xfc, 0xfe, 0xff
		};
		u_char j;

		for (j = 0x80; (j & *cp) != 0; j >>= 1)
			bit++;
		if (cp != (cplim - 1) || *cp != normal_chars[bit])
			isnormal = false;
	}
	bit += (cp - mask) << 3;
	x->rn_bit = -1 - bit;
	if (isnormal)
		x->rn_flags |= RNF_NORMAL;
	return (x);
}

/*
 * Compare the two netmasks and return true if netmask <m> is more
 * specific than netmask <n>.
 *
 * NOTE: arbitrary ordering for non-contiguous masks.
 */
static bool
rn_lexobetter(const void *_m, const void *_n)
{
	const u_char *m, *n, *lim;

	m = _m;
	n = _n;

	if (clen(m) > clen(n)) {
		/* not really, but need to check longer one first */
		return (true);
	}

	if (clen(m) == clen(n)) {
		for (lim = m + clen(m); m < lim; m++, n++) {
			if (*m > *n)
				return (true);
		}
	}

	return (false);
}

static struct radix_mask *
rn_new_radix_mask(struct radix_node *node, struct radix_mask *nextmask)
{
	struct radix_mask *m;

	m = MKGet(&rn_mkfreelist[mycpuid]);
	if (m == NULL) {
		log(LOG_ERR, "Mask for route not entered\n");
		return (NULL);
	}

	bzero(m, sizeof(*m));
	m->rm_bit = node->rn_bit;
	m->rm_flags = node->rn_flags;
	if (m->rm_flags & RNF_NORMAL)
		m->rm_leaf = node;
	else
		m->rm_mask = node->rn_mask;
	m->rm_next = nextmask;
	node->rn_mklist = m;

	return (m);
}

/*
 * Add the route (key, mask) to the radix tree <head> using the given
 * nodes <nodes>.  The netmask <mask> is NULL for a host route.
 *
 * Return the node of the inserted route on success.  Otherwise, return
 * NULL if the following happened:
 * - failed to add the netmask to the mask tree (e.g., out of memory)
 * - the identical route already exists
 *
 * NOTE: The address <key> and netmask <mask> must be of the same data
 *       structure (e.g., both 'struct sockaddr_in') so that they have the
 *       same skip bytes and data length.
 */
struct radix_node *
rn_addroute(const void *key, const void *mask,
	    struct radix_node_head *head, struct radix_node nodes[2])
{
	struct radix_node *top, *t, *x, *tt, *saved_tt;
	struct radix_mask *m, **mp;
	int bit, bit_leaf;
	bool keyduplicated;
	const void *mmask;

	top = head->rnh_treetop;
	x = NULL;
	bit = bit_leaf = 0;

	/*
	 * In dealing with non-contiguous masks, there may be
	 * many different routes which have the same mask.
	 * We will find it useful to have a unique pointer to
	 * the mask to speed avoiding duplicate references at
	 * nodes and possibly save time in calculating indices.
	 */
	if (mask != NULL) {
		if ((x = rn_addmask(mask, false, top->rn_offset,
				    head->rnh_maskhead)) == NULL)
			return (NULL);
		bit_leaf = x->rn_bit;
		bit = -1 - x->rn_bit;
		mask = x->rn_key;
	}
	/*
	 * Deal with duplicated keys: attach node to previous instance
	 */
	saved_tt = tt = rn_insert(key, head, &keyduplicated, nodes);
	if (keyduplicated) {
		/*
		 * Deal with duplicated key: attach node to previous instance.
		 *
		 * The masks for a duplicated key are sorted in the same way
		 * as in a mask list -- most specific to least specific.
		 * This may require the unfortunate nuisance of relocating
		 * the head of the list.
		 *
		 * If the mask is NULL (i.e., a host route), it's placed at
		 * the beginning (i.e., list head).
		 *
		 * If the mask is not duplicated, we wouldn't find it among
		 * possible duplicate key entries anyway, so the test below
		 * doesn't hurt.
		 */
		for (t = tt; tt != NULL; t = tt, tt = tt->rn_dupedkey) {
			if (tt->rn_mask == mask)
				return (NULL); /* same route already exists */
			if (mask == NULL /* host route */ ||
			    (tt->rn_mask != NULL &&
			     ((bit_leaf < tt->rn_bit) /* index(mask) > node */
			      || rn_refines(mask, tt->rn_mask)
			      || rn_lexobetter(mask, tt->rn_mask))))
				break;
		}
		if (tt == saved_tt) {
			struct	radix_node *xx = x;
			/* link in at head of list */
			(tt = nodes)->rn_dupedkey = t;
			tt->rn_flags = t->rn_flags;
			tt->rn_parent = x = t->rn_parent;
			t->rn_parent = tt;			/* parent */
			if (x->rn_left == t)
				x->rn_left = tt;
			else
				x->rn_right = tt;
			saved_tt = tt; x = xx;
		} else {
			(tt = nodes)->rn_dupedkey = t->rn_dupedkey;
			t->rn_dupedkey = tt;
			tt->rn_parent = t;			/* parent */
			if (tt->rn_dupedkey != NULL)		/* parent */
				tt->rn_dupedkey->rn_parent = tt; /* parent */
		}
		tt->rn_key = key;
		tt->rn_bit = -1;
		tt->rn_flags = RNF_ACTIVE;
#ifdef RN_DEBUG
		tt->rn_info = rn_nodenum++;
		tt->rn_twin = tt + 1;
		tt->rn_twin->rn_info = rn_nodenum++;
		tt->rn_ybro = rn_clist;
		rn_clist = tt;
#endif
	}

	/*
	 * Put mask in tree.
	 */
	if (mask != NULL) {
		tt->rn_mask = mask;
		tt->rn_bit = x->rn_bit;
		tt->rn_flags |= x->rn_flags & RNF_NORMAL;
	}
	t = saved_tt->rn_parent;
	if (keyduplicated)
		goto on2;
	bit_leaf = -1 - t->rn_bit;
	if (t->rn_right == saved_tt)
		x = t->rn_left;
	else
		x = t->rn_right;
	/* Promote general routes from below */
	if (x->rn_bit < 0) {
		mp = &t->rn_mklist;
		while (x != NULL) {
			if (x->rn_mask != NULL &&
			    x->rn_bit >= bit_leaf &&
			    x->rn_mklist == NULL) {
				*mp = m = rn_new_radix_mask(x, NULL);
				if (m != NULL)
					mp = &m->rm_next;
			}
			x = x->rn_dupedkey;
		}
	} else if (x->rn_mklist != NULL) {
		/* Skip over masks whose index is > that of new node. */
		for (mp = &x->rn_mklist; (m = *mp) != NULL; mp = &m->rm_next) {
			if (m->rm_bit >= bit_leaf)
				break;
		}
		t->rn_mklist = m;
		*mp = NULL;
	}

on2:
	if (mask == NULL || bit > t->rn_bit)
		return (tt); /* can't lift at all */

	/*
	 * Add new route to the highest possible ancestor's list.
	 */
	bit_leaf = tt->rn_bit;
	do {
		x = t;
		t = t->rn_parent;
	} while (bit <= t->rn_bit && x != top);
	/*
	 * Search through routes associated with node to
	 * insert new route according to index.
	 * Need same criteria as when sorting dupedkeys to avoid
	 * double loop on deletion.
	 */
	for (mp = &x->rn_mklist; (m = *mp) != NULL; mp = &m->rm_next) {
		if (m->rm_bit < bit_leaf)
			continue;
		if (m->rm_bit > bit_leaf)
			break;
		if (m->rm_flags & RNF_NORMAL) {
			mmask = m->rm_leaf->rn_mask;
			if (tt->rn_flags & RNF_NORMAL) {
			    log(LOG_ERR,
			        "Non-unique normal route, mask not entered\n");
				return (tt);
			}
		} else
			mmask = m->rm_mask;
		if (mmask == mask) {
			m->rm_refs++;
			tt->rn_mklist = m;
			return (tt);
		}
		if (rn_refines(mask, mmask) || rn_lexobetter(mask, mmask))
			break;
	}
	*mp = rn_new_radix_mask(tt, *mp);
	return (tt);
}

struct radix_node *
rn_delete(const void *key, const void *mask, struct radix_node_head *head)
{
	struct radix_node *top, *t, *p, *x, *tt, *saved_tt, *dupedkey;
	struct radix_mask *m, *saved_m, **mp;
	int bit, head_off, klen, cpu;

	cpu = mycpuid;
	x = head->rnh_treetop;
	tt = rn_search(key, x);
	head_off = x->rn_offset;
	klen =  clen(key);
	saved_tt = tt;
	top = x;
	if (tt == NULL ||
	    bcmp((const u_char *)key + head_off, tt->rn_key + head_off,
		 klen - head_off) != 0)
		return (NULL);

	/*
	 * Delete our route from mask lists.
	 */
	if (mask != NULL) {
		if ((x = rn_addmask(mask, true, head_off,
				    head->rnh_maskhead)) == NULL)
			return (NULL);
		mask = x->rn_key;
		while (tt->rn_mask != mask) {
			if ((tt = tt->rn_dupedkey) == NULL)
				return (NULL);
		}
	}
	if (tt->rn_mask == NULL || (saved_m = m = tt->rn_mklist) == NULL)
		goto on1;
	if (tt->rn_flags & RNF_NORMAL) {
		if (m->rm_leaf != tt || m->rm_refs > 0) {
			log(LOG_ERR, "rn_delete: inconsistent annotation\n");
			return (NULL);  /* dangling ref could cause disaster */
		}
	} else {
		if (m->rm_mask != tt->rn_mask) {
			log(LOG_ERR, "rn_delete: inconsistent annotation\n");
			goto on1;
		}
		if (--m->rm_refs >= 0)
			goto on1;
	}
	bit = -1 - tt->rn_bit;
	t = saved_tt->rn_parent;
	if (bit > t->rn_bit)
		goto on1; /* Wasn't lifted at all */

	do {
		x = t;
		t = t->rn_parent;
	} while (bit <= t->rn_bit && x != top);
	for (mp = &x->rn_mklist; (m = *mp) != NULL; mp = &m->rm_next)
		if (m == saved_m) {
			*mp = m->rm_next;
			MKFree(&rn_mkfreelist[cpu], m);
			break;
		}
	if (m == NULL) {
		log(LOG_ERR, "rn_delete: couldn't find our annotation\n");
		if (tt->rn_flags & RNF_NORMAL)
			return (NULL); /* Dangling ref to us */
	}

on1:
	/*
	 * Eliminate us from tree
	 */
	if (tt->rn_flags & RNF_ROOT)
		return (NULL);

#ifdef RN_DEBUG
	/* Get us out of the creation list */
	for (t = rn_clist; t != NULL && t->rn_ybro != tt; t = t->rn_ybro)
		;
	if (t != NULL)
		t->rn_ybro = tt->rn_ybro;
#endif

	t = tt->rn_parent;
	dupedkey = saved_tt->rn_dupedkey;
	if (dupedkey != NULL) {
		/*
		 * at this point, tt is the deletion target and saved_tt
		 * is the head of the dupekey chain
		 */
		if (tt == saved_tt) {
			/* remove from head of chain */
			x = dupedkey;
			x->rn_parent = t;
			if (t->rn_left == tt)
				t->rn_left = x;
			else
				t->rn_right = x;
		} else {
			/* find node in front of tt on the chain */
			for (x = p = saved_tt; p != NULL && p->rn_dupedkey != tt;)
				p = p->rn_dupedkey;
			if (p) {
				p->rn_dupedkey = tt->rn_dupedkey;
				if (tt->rn_dupedkey)		/* parent */
					tt->rn_dupedkey->rn_parent = p;
								/* parent */
			} else {
				log(LOG_ERR, "rn_delete: couldn't find us\n");
			}
		}
		t = tt + 1;
		if  (t->rn_flags & RNF_ACTIVE) {
#ifndef RN_DEBUG
			*++x = *t;
			p = t->rn_parent;
#else
			bit = t->rn_info;
			*++x = *t;
			t->rn_info = bit;
			p = t->rn_parent;
#endif
			if (p->rn_left == t)
				p->rn_left = x;
			else
				p->rn_right = x;
			x->rn_left->rn_parent = x;
			x->rn_right->rn_parent = x;
		}
		goto out;
	}
	if (t->rn_left == tt)
		x = t->rn_right;
	else
		x = t->rn_left;
	p = t->rn_parent;
	if (p->rn_right == t)
		p->rn_right = x;
	else
		p->rn_left = x;
	x->rn_parent = p;
	/*
	 * Demote routes attached to us.
	 */
	if (t->rn_mklist != NULL) {
		if (x->rn_bit >= 0) {
			for (mp = &x->rn_mklist; (m = *mp) != NULL;)
				mp = &m->rm_next;
			*mp = t->rn_mklist;
		} else {
			/*
			 * If there are any (key, mask) pairs in a sibling
			 * duped-key chain, some subset will appear sorted
			 * in the same order attached to our mklist.
			 */
			for (m = t->rn_mklist; m && x; x = x->rn_dupedkey)
				if (m == x->rn_mklist) {
					struct radix_mask *mm = m->rm_next;

					x->rn_mklist = NULL;
					if (--(m->rm_refs) < 0)
						MKFree(&rn_mkfreelist[cpu], m);
					m = mm;
				}
			if (m) {
				log(LOG_ERR,
				    "rn_delete: Orphaned Mask %p at %p\n",
				    (void *)m, (void *)x);
			}
		}
	}
	/*
	 * We may be holding an active internal node in the tree.
	 */
	x = tt + 1;
	if (t != x) {
#ifndef RN_DEBUG
		*t = *x;
#else
		bit = t->rn_info;
		*t = *x;
		t->rn_info = bit;
#endif
		t->rn_left->rn_parent = t;
		t->rn_right->rn_parent = t;
		p = x->rn_parent;
		if (p->rn_left == x)
			p->rn_left = t;
		else
			p->rn_right = t;
	}

out:
	tt[0].rn_flags &= ~RNF_ACTIVE;
	tt[1].rn_flags &= ~RNF_ACTIVE;
	return (tt);
}

/*
 * This is the same as rn_walktree() except for the parameters and the
 * exit.
 */
static int
rn_walktree_from(struct radix_node_head *h, const void *_addr,
		 const void *_mask, walktree_f_t *f, void *w)
{
	struct radix_node *rn, *base, *next, *last;
	const u_char *addr, *mask;
	bool stopping;
	int lastb, error;

	addr = _addr;
	mask = _mask;
	last = NULL;
	stopping = false;

	/*
	 * rn_search_m() is sort-of-open-coded here.  We cannot use that
	 * function because we need to keep track of the last node seen.
	 */
	/* kprintf("about to search\n"); */
	for (rn = h->rnh_treetop; rn->rn_bit >= 0; ) {
		last = rn;
		/* kprintf("rn_bit %d, rn_bmask %x, mask[rn_offset] %x\n",
		       rn->rn_bit, rn->rn_bmask, mask[rn->rn_offset]); */
		if (!(rn->rn_bmask & mask[rn->rn_offset])) {
			break;
		}
		if (rn->rn_bmask & addr[rn->rn_offset]) {
			rn = rn->rn_right;
		} else {
			rn = rn->rn_left;
		}
	}
	/* kprintf("done searching\n"); */

	/*
	 * Two cases: either we stepped off the end of our mask,
	 * in which case last == rn, or we reached a leaf, in which
	 * case we want to start from the last node we looked at.
	 * Either way, last is the node we want to start from.
	 */
	rn = last;
	lastb = rn->rn_bit;

	/* kprintf("rn %p, lastb %d\n", rn, lastb);*/

	/*
	 * This gets complicated because we may delete the node
	 * while applying the function f to it, so we need to calculate
	 * the successor node in advance.
	 */
	while (rn->rn_bit >= 0)
		rn = rn->rn_left;

	while (!stopping) {
		/* kprintf("node %p (%d)\n", rn, rn->rn_bit); */
		base = rn;
		/* If at right child go back up, otherwise, go right */
		while (rn->rn_parent->rn_right == rn &&
		    !(rn->rn_flags & RNF_ROOT)) {
			rn = rn->rn_parent;

			/* if went up beyond last, stop */
			if (rn->rn_bit < lastb) {
				stopping = true;
				/* kprintf("up too far\n"); */
			}
		}

		/* Find the next *leaf* since next node might vanish, too */
		for (rn = rn->rn_parent->rn_right; rn->rn_bit >= 0;)
			rn = rn->rn_left;
		next = rn;
		/* Process leaves */
		while ((rn = base) != NULL) {
			base = rn->rn_dupedkey;
			/* kprintf("leaf %p\n", rn); */
			if (!(rn->rn_flags & RNF_ROOT) && (error = (*f)(rn, w)))
				return (error);
		}
		rn = next;

		if (rn->rn_flags & RNF_ROOT) {
			/* kprintf("root, stopping"); */
			stopping = true;
		}
	}

	return 0;
}

static int
rn_walktree_at(struct radix_node_head *h, const void *addr, const void *mask,
	       walktree_f_t *f, void *w)
{
	struct radix_node *rn, *base, *next;
	int error;

	rn = h->rnh_treetop;

	/*
	 * This gets complicated because we may delete the node
	 * while applying the function f to it, so we need to calculate
	 * the successor node in advance.
	 */
	if (addr == NULL) {
		/* First time through node, go left */
		while (rn->rn_bit >= 0)
			rn = rn->rn_left;
	} else {
		if (mask != NULL)
			rn = rn_search_m(addr, mask, rn);
		else
			rn = rn_search(addr, rn);
	}
	for (;;) {
		base = rn;
		/* If at right child go back up, otherwise, go right */
		while (rn->rn_parent->rn_right == rn &&
		    !(rn->rn_flags & RNF_ROOT))
			rn = rn->rn_parent;
		/* Find the next *leaf* since next node might vanish, too */
		for (rn = rn->rn_parent->rn_right; rn->rn_bit >= 0;)
			rn = rn->rn_left;
		next = rn;
		/* Process leaves */
		while ((rn = base)) {
			base = rn->rn_dupedkey;
			if (!(rn->rn_flags & RNF_ROOT) && (error = (*f)(rn, w)))
				return (error);
		}
		rn = next;
		if (rn->rn_flags & RNF_ROOT)
			return (0);
	}
	/* NOTREACHED */
}

static int
rn_walktree(struct radix_node_head *h, walktree_f_t *f, void *w)
{
	return rn_walktree_at(h, NULL, NULL, f, w);
}

/*
 * Allocate and initialize an empty radix tree at <head>.
 *
 * The created radix_node_head embeds 3 nodes in the order of
 * {left,root,right}.  These nodes are flagged with RNF_ROOT and thus
 * cannot be freed.  The left and right leaves are initialized with
 * all-zero and all-one keys, respectively, and with the significant
 * byte starting at <off_bytes>.
 *
 * The <maskhead> refers to another radix tree for storing the network
 * masks (so aka mask tree).  It is also created by this function with
 * <maskhead>=NULL; the <off_bytes> parameter is ignored and auto set
 * to be zero (0).  The reason of requiring <off_bytes> be zero is that
 * a mask tree can be shared with multiple radix trees of different
 * address families that have different offset bytes; e.g.,
 * offsetof(struct sockaddr_in, sin_addr) !=
 * offsetof(struct sockaddr_in6, sin6_addr).
 *
 * Return 1 on success, 0 on error.
 */
int
rn_inithead(struct radix_node_head **head, struct radix_node_head *maskhead,
	    int off_bytes)
{
	struct radix_node_head *rnh;
	struct radix_node *root, *left, *right;

	if (*head != NULL)	/* already initialized */
		return (1);

	R_Malloc(rnh, struct radix_node_head *, sizeof *rnh);
	if (rnh == NULL)
		return (0);

	if (maskhead == NULL)	/* mask tree initialization */
		off_bytes = 0;
	if (off_bytes >= RN_MAXKEYLEN)	/* prevent possible misuse */
		panic("%s: invalid off_bytes=%d", __func__, off_bytes);

	bzero(rnh, sizeof *rnh);
	*head = rnh;

	root = rn_newpair(rn_zeros, off_bytes * NBBY, rnh->rnh_nodes);
	right = &rnh->rnh_nodes[2];
	root->rn_parent = root;
	root->rn_flags = RNF_ROOT | RNF_ACTIVE;
	root->rn_right = right;

	left = root->rn_left;
	left->rn_bit = -1 - off_bytes * NBBY;
	left->rn_flags = root->rn_flags;

	*right = *left;
	right->rn_key = rn_ones;

	rnh->rnh_treetop = root;
	rnh->rnh_maskhead = maskhead;

	rnh->rnh_addaddr = rn_addroute;
	rnh->rnh_deladdr = rn_delete;
	rnh->rnh_matchaddr = rn_match;
	rnh->rnh_lookup = rn_lookup;
	rnh->rnh_walktree = rn_walktree;
	rnh->rnh_walktree_from = rn_walktree_from;
	rnh->rnh_walktree_at = rn_walktree_at;

	return (1);
}

/*
 * Callback function to be used in rn_flush() to empty a mask tree.
 */
void
rn_freemask(struct radix_node *rn)
{
	if (rn->rn_mask != NULL)
		panic("%s: not a mask node", __func__);

	R_Free(rn);
}

struct rn_flush_ctx {
	struct radix_node_head *head;
	freenode_f_t *f;
};

static int
rn_flush_walker(struct radix_node *rn, void *arg)
{
	struct rn_flush_ctx *ctx = arg;
	struct radix_node *node;

	node = ctx->head->rnh_deladdr(rn->rn_key, rn->rn_mask, ctx->head);
	if (node != rn) {
		panic("%s: deleted wrong node: %p, want: %p",
		      __func__, node, rn);
	}
	if (ctx->f)
		ctx->f(rn);

	return 0;
}

#define IS_EMPTY(head) \
	(((head)->rnh_treetop == &(head)->rnh_nodes[1]) && \
	 ((head)->rnh_treetop->rn_left == &(head)->rnh_nodes[0]) && \
	 ((head)->rnh_treetop->rn_right == &(head)->rnh_nodes[2]))

/*
 * Flush all nodes in the radix tree at <head>.
 * If the callback function <f> is specified, it is called against every
 * flushed node to allow the caller to do extra cleanups.
 */
void
rn_flush(struct radix_node_head *head, freenode_f_t *f)
{
	struct rn_flush_ctx ctx;

	if (f == rn_freemask && head->rnh_maskhead != NULL)
		panic("%s: rn_freemask() used with non-mask tree", __func__);

	ctx.head = head;
	ctx.f = f;
	head->rnh_walktree(head, rn_flush_walker, &ctx);

	if (!IS_EMPTY(head))
		panic("%s: failed to flush all nodes", __func__);
}

/*
 * Free an empty radix tree at <head>.
 *
 * NOTE: The radix tree must be first emptied by rn_flush().
 */
void
rn_freehead(struct radix_node_head *head)
{
	if (!IS_EMPTY(head))
		panic("%s: radix tree not empty", __func__);

	R_Free(head);
}

#ifdef _KERNEL

static void
rn_init_handler(netmsg_t msg)
{
	int cpu = mycpuid;

	ASSERT_NETISR_NCPUS(cpu);
	if (rn_inithead(&mask_rnheads[cpu], NULL, 0) == 0)
		panic("%s: failed to create mask tree", __func__);

	netisr_forwardmsg(&msg->base, cpu + 1);
}

void
rn_init(void)
{
	struct netmsg_base msg;
	struct domain *dom;

	SLIST_FOREACH(dom, &domains, dom_next) {
		if (dom->dom_maxrtkey > RN_MAXKEYLEN) {
			panic("domain %s maxkey too big %d/%d",
			      dom->dom_name, dom->dom_maxrtkey, RN_MAXKEYLEN);
		}
	}

	netmsg_init(&msg, NULL, &curthread->td_msgport, 0, rn_init_handler);
	netisr_domsg_global(&msg);
}

struct radix_node_head *
rn_cpumaskhead(int cpu)
{
	ASSERT_NETISR_NCPUS(cpu);
	KKASSERT(mask_rnheads[cpu] != NULL);
	return mask_rnheads[cpu];
}

#else /* !_KERNEL */

void
rn_init(void)
{
	if (rn_inithead(&mask_rnheads[0], NULL, 0) == 0)
		panic("%s: failed to create mask tree", __func__);
}

struct radix_node_head *
rn_cpumaskhead(int cpu __unused)
{
	return mask_rnheads[0];
}

#endif /* _KERNEL */
