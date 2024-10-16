/*	$FreeBSD: src/sys/opencrypto/crypto.c,v 1.28 2007/10/20 23:23:22 julian Exp $	*/
/*-
 * Copyright (c) 2002-2006 Sam Leffler.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Cryptographic Subsystem.
 *
 * This code is derived from the Openbsd Cryptographic Framework (OCF)
 * that has the copyright shown below.  Very little of the original
 * code remains.
 */

/*-
 * The author of this code is Angelos D. Keromytis (angelos@cis.upenn.edu)
 *
 * This code was written by Angelos D. Keromytis in Athens, Greece, in
 * February 2000. Network Security Technologies Inc. (NSTI) kindly
 * supported the development of this code.
 *
 * Copyright (c) 2000, 2001 Angelos D. Keromytis
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
 */

#include "opt_ddb.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/eventhandler.h>
#include <sys/kernel.h>
#include <sys/kthread.h>
#include <sys/lock.h>
#include <sys/module.h>
#include <sys/malloc.h>
#include <sys/proc.h>
#include <sys/sysctl.h>
#include <sys/objcache.h>

#include <sys/thread2.h>

#include <ddb/ddb.h>

#include <opencrypto/cryptodev.h>

#include <sys/kobj.h>
#include <sys/bus.h>
#include "cryptodev_if.h"

/*
 * Crypto drivers register themselves by allocating a slot in the
 * crypto_drivers table with crypto_get_driverid() and then registering
 * each algorithm they support with crypto_register().
 */
static	struct lock crypto_drivers_lock;	/* lock on driver table */
#define	CRYPTO_DRIVER_LOCK()	lockmgr(&crypto_drivers_lock, LK_EXCLUSIVE)
#define	CRYPTO_DRIVER_UNLOCK()	lockmgr(&crypto_drivers_lock, LK_RELEASE)
#define	CRYPTO_DRIVER_ASSERT()	KKASSERT(lockstatus(&crypto_drivers_lock, curthread) != 0)

/*
 * Crypto device/driver capabilities structure.
 *
 * Synchronization:
 * (d) - protected by CRYPTO_DRIVER_LOCK()
 * Not tagged fields are read-only.
 */
struct cryptocap {
	device_t	cc_dev;			/* (d) device/driver */
	u_int32_t	cc_sessions;		/* (d) # of sessions */
	u_int32_t	cc_koperations;		/* (d) # os asym operations */
	/*
	 * Largest possible operator length (in bits) for each type of
	 * encryption algorithm. XXX not used
	 */
	u_int16_t	cc_max_op_len[CRYPTO_ALGORITHM_MAX + 1];
	u_int8_t	cc_alg[CRYPTO_ALGORITHM_MAX + 1];
	u_int8_t	cc_kalg[CRK_ALGORITHM_MAX + 1];

	int		cc_flags;		/* (d) flags */
#define CRYPTOCAP_F_CLEANUP	0x80000000	/* needs resource cleanup */
};
static	struct cryptocap *crypto_drivers = NULL;
static	int crypto_drivers_num = 0;

/*
 * Crypto op and desciptor data structures are allocated
 * from separate object caches.
 */
static struct objcache *cryptop_oc, *cryptodesc_oc;

static MALLOC_DEFINE(M_CRYPTO_OP, "crypto op", "crypto op");
static MALLOC_DEFINE(M_CRYPTO_DESC, "crypto desc", "crypto desc");

int	crypto_userasymcrypto = 1;	/* userland may do asym crypto reqs */
SYSCTL_INT(_kern, OID_AUTO, userasymcrypto, CTLFLAG_RW,
	   &crypto_userasymcrypto, 0,
	   "Enable/disable user-mode access to asymmetric crypto support");
int	crypto_devallowsoft = 0;	/* only use hardware crypto for asym */
SYSCTL_INT(_kern, OID_AUTO, cryptodevallowsoft, CTLFLAG_RW,
	   &crypto_devallowsoft, 0,
	   "Enable/disable use of software asym crypto support");

MALLOC_DEFINE(M_CRYPTO_DATA, "crypto", "crypto session records");

static	void crypto_destroy(void);

static struct cryptostats cryptostats;
SYSCTL_STRUCT(_kern, OID_AUTO, crypto_stats, CTLFLAG_RW, &cryptostats,
	    cryptostats, "Crypto system statistics");

static int
crypto_init(void)
{
	int error;

	lockinit(&crypto_drivers_lock, "crypto driver table", 0, LK_CANRECURSE);

	cryptop_oc = objcache_create_simple(M_CRYPTO_OP, sizeof(struct cryptop));
	cryptodesc_oc = objcache_create_simple(M_CRYPTO_DESC,
				sizeof(struct cryptodesc));
	if (cryptodesc_oc == NULL || cryptop_oc == NULL) {
		kprintf("crypto_init: cannot setup crypto caches\n");
		error = ENOMEM;
		goto bad;
	}

	crypto_drivers_num = CRYPTO_DRIVERS_INITIAL;
	crypto_drivers = kmalloc(crypto_drivers_num * sizeof(struct cryptocap),
				 M_CRYPTO_DATA, M_WAITOK | M_ZERO);

	return 0;
bad:
	crypto_destroy();
	return error;
}

static void
crypto_destroy(void)
{
	/* XXX flush queues??? */

	/*
	 * Reclaim dynamically allocated resources.
	 */
	if (crypto_drivers != NULL)
		kfree(crypto_drivers, M_CRYPTO_DATA);

	if (cryptodesc_oc != NULL)
		objcache_destroy(cryptodesc_oc);
	if (cryptop_oc != NULL)
		objcache_destroy(cryptop_oc);
	lockuninit(&crypto_drivers_lock);
}

static struct cryptocap *
crypto_checkdriver(u_int32_t hid)
{
	if (crypto_drivers == NULL)
		return NULL;
	return (hid >= crypto_drivers_num ? NULL : &crypto_drivers[hid]);
}

/*
 * Compare a driver's list of supported algorithms against another
 * list; return non-zero if all algorithms are supported.
 */
static int
driver_suitable(const struct cryptocap *cap, const struct cryptoini *cri)
{
	/* See if all the algorithms are supported. */
	if (cri && cap->cc_alg[cri->cri_alg] == 0)
		return 0;
	return 1;
}

/*
 * Select a driver for a new session that supports the specified
 * algorithms and, optionally, is constrained according to the flags.
 * The algorithm we use here is pretty stupid; just use the
 * first driver that supports all the algorithms we need. If there
 * are multiple drivers we choose the driver with the fewest active
 * sessions.  We prefer hardware-backed drivers to software ones.
 *
 * XXX We need more smarts here (in real life too, but that's
 * XXX another story altogether).
 */
static struct cryptocap *
crypto_select_driver(const struct cryptoini *cri, int flags)
{
	struct cryptocap *cap, *best;
	int match, hid;

	CRYPTO_DRIVER_ASSERT();

	/*
	 * Look first for hardware crypto devices if permitted.
	 */
	if (flags & CRYPTOCAP_F_HARDWARE)
		match = CRYPTOCAP_F_HARDWARE;
	else
		match = CRYPTOCAP_F_SOFTWARE;
	best = NULL;
again:
	for (hid = 0; hid < crypto_drivers_num; hid++) {
		cap = &crypto_drivers[hid];
		/*
		 * If it's not initialized, is in the process of
		 * going away, or is not appropriate (hardware
		 * or software based on match), then skip.
		 */
		if (cap->cc_dev == NULL ||
		    (cap->cc_flags & CRYPTOCAP_F_CLEANUP) ||
		    (cap->cc_flags & match) == 0)
			continue;

		/* verify all the algorithms are supported. */
		if (driver_suitable(cap, cri)) {
			if (best == NULL ||
			    cap->cc_sessions < best->cc_sessions)
				best = cap;
		}
	}
	if (best != NULL)
		return best;
	if (match == CRYPTOCAP_F_HARDWARE && (flags & CRYPTOCAP_F_SOFTWARE)) {
		/* sort of an Algol 68-style for loop */
		match = CRYPTOCAP_F_SOFTWARE;
		goto again;
	}
	return best;
}

/*
 * Create a new session.  The crid argument specifies a crypto
 * driver to use or constraints on a driver to select (hardware
 * only, software only, either).  Whatever driver is selected
 * must be capable of the requested crypto algorithms.
 */
int
crypto_newsession(u_int64_t *sid, struct cryptoini *cri, int crid)
{
	struct cryptocap *cap;
	u_int32_t hid, lid;
	int err;

	CRYPTO_DRIVER_LOCK();
	if ((crid & (CRYPTOCAP_F_HARDWARE | CRYPTOCAP_F_SOFTWARE)) == 0) {
		/*
		 * Use specified driver; verify it is capable.
		 */
		cap = crypto_checkdriver(crid);
		if (cap != NULL && !driver_suitable(cap, cri))
			cap = NULL;
	} else {
		/*
		 * No requested driver; select based on crid flags.
		 */
		cap = crypto_select_driver(cri, crid);
		/*
		 * if NULL then can't do everything in one session.
		 * XXX Fix this. We need to inject a "virtual" session
		 * XXX layer right about here.
		 */
	}
	if (cap != NULL) {
		/* Call the driver initialization routine. */
		hid = cap - crypto_drivers;
		lid = hid;		/* Pass the driver ID. */
		err = CRYPTODEV_NEWSESSION(cap->cc_dev, &lid, cri);
		if (err == 0) {
			(*sid) = (cap->cc_flags & 0xff000000)
			       | (hid & 0x00ffffff);
			(*sid) <<= 32;
			(*sid) |= (lid & 0xffffffff);
			cap->cc_sessions++;
		}
	} else
		err = EINVAL;
	CRYPTO_DRIVER_UNLOCK();
	return err;
}

static void
crypto_remove(struct cryptocap *cap)
{

	KKASSERT(lockstatus(&crypto_drivers_lock, curthread) != 0);
	if (cap->cc_sessions == 0 && cap->cc_koperations == 0)
		bzero(cap, sizeof(*cap));
}

/*
 * Delete an existing session (or a reserved session on an unregistered
 * driver).
 */
int
crypto_freesession(u_int64_t sid)
{
	struct cryptocap *cap;
	u_int32_t hid;
	int err;

	CRYPTO_DRIVER_LOCK();

	if (crypto_drivers == NULL) {
		err = EINVAL;
		goto done;
	}

	/* Determine two IDs. */
	hid = CRYPTO_SESID2HID(sid);

	if (hid >= crypto_drivers_num) {
		err = ENOENT;
		goto done;
	}
	cap = &crypto_drivers[hid];

	if (cap->cc_sessions)
		cap->cc_sessions--;

	/* Call the driver cleanup routine, if available. */
	err = CRYPTODEV_FREESESSION(cap->cc_dev, sid);

	if (cap->cc_flags & CRYPTOCAP_F_CLEANUP)
		crypto_remove(cap);

done:
	CRYPTO_DRIVER_UNLOCK();
	return err;
}

/*
 * Return an unused driver id.  Used by drivers prior to registering
 * support for the algorithms they handle.
 */
int32_t
crypto_get_driverid(device_t dev, int flags)
{
	struct cryptocap *newdrv;
	int i;

	if ((flags & (CRYPTOCAP_F_HARDWARE | CRYPTOCAP_F_SOFTWARE)) == 0) {
		kprintf("%s: no flags specified when registering driver\n",
		    device_get_nameunit(dev));
		return -1;
	}

	CRYPTO_DRIVER_LOCK();

	for (i = 0; i < crypto_drivers_num; i++) {
		if (crypto_drivers[i].cc_dev == NULL &&
		    (crypto_drivers[i].cc_flags & CRYPTOCAP_F_CLEANUP) == 0) {
			break;
		}
	}

	/* Out of entries, allocate some more. */
	if (i == crypto_drivers_num) {
		/* Be careful about wrap-around. */
		if (2 * crypto_drivers_num <= crypto_drivers_num) {
			CRYPTO_DRIVER_UNLOCK();
			kprintf("crypto: driver count wraparound!\n");
			return -1;
		}

		newdrv = kmalloc(2 * crypto_drivers_num *
				 sizeof(struct cryptocap),
				 M_CRYPTO_DATA, M_WAITOK|M_ZERO);

		bcopy(crypto_drivers, newdrv,
		    crypto_drivers_num * sizeof(struct cryptocap));

		crypto_drivers_num *= 2;

		kfree(crypto_drivers, M_CRYPTO_DATA);
		crypto_drivers = newdrv;
	}

	/* NB: state is zero'd on free */
	crypto_drivers[i].cc_sessions = 1;	/* Mark */
	crypto_drivers[i].cc_dev = dev;
	crypto_drivers[i].cc_flags = flags;
	if (bootverbose)
		kprintf("crypto: assign %s driver id %u, flags %u\n",
		    device_get_nameunit(dev), i, flags);

	CRYPTO_DRIVER_UNLOCK();

	return i;
}

/*
 * Register support for a non-key-related algorithm.  This routine
 * is called once for each such algorithm supported by a driver.
 */
int
crypto_register(u_int32_t driverid, int alg, u_int16_t maxoplen,
		u_int32_t flags)
{
	struct cryptocap *cap;
	int err;

	CRYPTO_DRIVER_LOCK();

	cap = crypto_checkdriver(driverid);
	/* NB: algorithms are in the range [1..max] */
	if (cap != NULL &&
	    (CRYPTO_ALGORITHM_MIN <= alg && alg <= CRYPTO_ALGORITHM_MAX)) {
		/*
		 * XXX Do some performance testing to determine placing.
		 * XXX We probably need an auxiliary data structure that
		 * XXX describes relative performances.
		 */

		cap->cc_alg[alg] = flags | CRYPTO_ALG_FLAG_SUPPORTED;
		cap->cc_max_op_len[alg] = maxoplen;
		if (bootverbose)
			kprintf("crypto: %s registers alg %u flags %u maxoplen %u\n"
				, device_get_nameunit(cap->cc_dev)
				, alg
				, flags
				, maxoplen
			);
		cap->cc_sessions = 0;		/* Unmark */
		err = 0;
	} else
		err = EINVAL;

	CRYPTO_DRIVER_UNLOCK();
	return err;
}

static void
driver_finis(struct cryptocap *cap)
{
	u_int32_t ses, kops;

	CRYPTO_DRIVER_ASSERT();

	ses = cap->cc_sessions;
	kops = cap->cc_koperations;
	bzero(cap, sizeof(*cap));
	if (ses != 0 || kops != 0) {
		/*
		 * If there are pending sessions,
		 * just mark as invalid.
		 */
		cap->cc_flags |= CRYPTOCAP_F_CLEANUP;
		cap->cc_sessions = ses;
		cap->cc_koperations = kops;
	}
}

/*
 * Unregister a crypto driver. If there are pending sessions using it,
 * leave enough information around so that subsequent calls using those
 * sessions will correctly detect the driver has been unregistered and
 * reroute requests.
 */
int
crypto_unregister(u_int32_t driverid, int alg)
{
	struct cryptocap *cap;
	int i, err;

	CRYPTO_DRIVER_LOCK();
	cap = crypto_checkdriver(driverid);
	if (cap != NULL &&
	    (CRYPTO_ALGORITHM_MIN <= alg && alg <= CRYPTO_ALGORITHM_MAX) &&
	    cap->cc_alg[alg] != 0) {
		cap->cc_alg[alg] = 0;
		cap->cc_max_op_len[alg] = 0;

		/* Was this the last algorithm ? */
		for (i = 1; i <= CRYPTO_ALGORITHM_MAX; i++) {
			if (cap->cc_alg[i] != 0)
				break;
		}

		if (i == CRYPTO_ALGORITHM_MAX + 1)
			driver_finis(cap);
		err = 0;
	} else {
		err = EINVAL;
	}
	CRYPTO_DRIVER_UNLOCK();

	return err;
}

/*
 * Unregister all algorithms associated with a crypto driver.
 * If there are pending sessions using it, leave enough information
 * around so that subsequent calls using those sessions will
 * correctly detect the driver has been unregistered and reroute
 * requests.
 */
int
crypto_unregister_all(u_int32_t driverid)
{
	struct cryptocap *cap;
	int err;

	CRYPTO_DRIVER_LOCK();
	cap = crypto_checkdriver(driverid);
	if (cap != NULL) {
		driver_finis(cap);
		err = 0;
	} else {
		err = EINVAL;
	}
	CRYPTO_DRIVER_UNLOCK();

	return err;
}

static volatile int dispatch_rover;

/*
 * Add a crypto request to a queue, to be processed by the kernel thread.
 */
int
crypto_dispatch(struct cryptop *crp)
{
	struct cryptocap *cap;
	u_int32_t hid;
	int error = 0;

	KASSERT(crp != NULL, ("%s: crp == NULL", __func__));
	KASSERT(crp->crp_desc != NULL, ("%s: crp->crp_desc == NULL", __func__));

	cryptostats.cs_ops++;

	hid = CRYPTO_SESID2HID(crp->crp_sid);

	/*
	 * Dispatch the crypto op directly to the driver.
	 */
	cap = crypto_checkdriver(hid);
	/* Driver cannot disappeared when there is an active session. */
	KASSERT(cap != NULL, ("%s: Driver disappeared.", __func__));

	if (cap->cc_flags & CRYPTOCAP_F_CLEANUP) {
		u_int64_t nid;

		/*
		 * Driver has unregistered; migrate the session and return
		 * an error to the caller so they'll resubmit the op.
		 *
		 * XXX: What if there are more already queued requests for this
		 *      session?
		 */
		crypto_freesession(crp->crp_sid);

		/* XXX propagate flags from initial session? */
		if (crypto_newsession(&nid, &(crp->crp_desc->CRD_INI),
		    CRYPTOCAP_F_HARDWARE | CRYPTOCAP_F_SOFTWARE) == 0)
			crp->crp_sid = nid;

		crp->crp_flags |= CRYPTO_F_DONE;
		error = EAGAIN;
	} else {
		/*
		 * Invoke the driver to process the request.
		 */
		error = CRYPTODEV_PROCESS(cap->cc_dev, crp);
	}

	if (error)
		cryptostats.cs_errs++;
	return (error);
}

#ifdef DDB
static void
db_show_drivers(void)
{
	int hid;

	db_printf("%12s %4s %4s %8s %2s %2s\n"
		, "Device"
		, "Ses"
		, "Kops"
		, "Flags"
		, "QB"
		, "KB"
	);
	for (hid = 0; hid < crypto_drivers_num; hid++) {
		const struct cryptocap *cap = &crypto_drivers[hid];
		if (cap->cc_dev == NULL)
			continue;
		db_printf("%-12s %4u %4u %08x\n"
		    , device_get_nameunit(cap->cc_dev)
		    , cap->cc_sessions
		    , cap->cc_koperations
		    , cap->cc_flags
		);
	}
}

DB_SHOW_COMMAND(crypto, db_show_crypto)
{
	db_show_drivers();
	db_printf("\n");
}

#endif

int crypto_modevent(module_t mod, int type, void *unused);

/*
 * Initialization code, both for static and dynamic loading.
 * Note this is not invoked with the usual DECLARE_MODULE
 * mechanism but instead is listed as a dependency by the
 * cryptosoft driver.  This guarantees proper ordering of
 * calls on module load/unload.
 */
int
crypto_modevent(module_t mod, int type, void *unused)
{
	int error = EINVAL;

	switch (type) {
	case MOD_LOAD:
		error = crypto_init();
		if (error == 0 && bootverbose)
			kprintf("crypto: <crypto core>\n");
		break;
	case MOD_UNLOAD:
		/*XXX disallow if active sessions */
		error = 0;
		crypto_destroy();
		return 0;
	}
	return error;
}
MODULE_VERSION(crypto, 1);
MODULE_DEPEND(crypto, zlib, 1, 1, 1);
