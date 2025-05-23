/*
 * Copyright (c) 2003,2004 The DragonFly Project.  All rights reserved.
 *
 * This code is derived from software contributed to The DragonFly Project
 * by Matthew Dillon <dillon@backplane.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 * 3. Neither the name of The DragonFly Project nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific, prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE
 * COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * Copyright (c) 1997, 1998 Poul-Henning Kamp <phk@FreeBSD.org>
 * Copyright (c) 1982, 1986, 1991, 1993
 *	The Regents of the University of California.  All rights reserved.
 * (c) UNIX System Laboratories, Inc.
 * All or some portions of this file are derived from material licensed
 * to the University of California by American Telephone and Telegraph
 * Co. or Unix System Laboratories, Inc. and are reproduced herein with
 * the permission of UNIX System Laboratories, Inc.
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
 *	@(#)kern_clock.c	8.5 (Berkeley) 1/21/94
 * $FreeBSD: src/sys/kern/kern_clock.c,v 1.105.2.10 2002/10/17 13:19:40 maxim Exp $
 */

#include "opt_ntp.h"
#include "opt_pctrack.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/callout.h>
#include <sys/kernel.h>
#include <sys/kinfo.h>
#include <sys/proc.h>
#include <sys/malloc.h>
#include <sys/resource.h>
#include <sys/resourcevar.h>
#include <sys/signalvar.h>
#include <sys/caps.h>
#include <sys/timex.h>
#include <sys/timepps.h>
#include <sys/upmap.h>
#include <sys/lock.h>
#include <sys/sysctl.h>
#include <sys/kcollect.h>
#include <sys/exislock.h>
#include <sys/exislock2.h>

#include <vm/vm.h>
#include <vm/pmap.h>
#include <vm/vm_map.h>
#include <vm/vm_extern.h>

#include <sys/thread2.h>
#include <sys/spinlock2.h>

#include <machine/cpu.h>
#include <machine/limits.h>
#include <machine/smp.h>
#include <machine/cpufunc.h>
#include <machine/specialreg.h>
#include <machine/clock.h>

#ifdef DEBUG_PCTRACK
static void do_pctrack(struct intrframe *frame, int which);
#endif

static void initclocks (void *dummy);
SYSINIT(clocks, SI_BOOT2_CLOCKS, SI_ORDER_FIRST, initclocks, NULL);

/*
 * Some of these don't belong here, but it's easiest to concentrate them.
 * Note that cpu_time counts in microseconds, but most userland programs
 * just compare relative times against the total by delta.
 */
struct kinfo_cputime cputime_percpu[MAXCPU];
#ifdef DEBUG_PCTRACK
struct kinfo_pcheader cputime_pcheader = { PCTRACK_SIZE, PCTRACK_ARYSIZE };
struct kinfo_pctrack cputime_pctrack[MAXCPU][PCTRACK_SIZE];
#endif

__read_mostly static int sniff_enable = 1;
__read_mostly static int sniff_target = -1;
__read_mostly static int clock_debug2 = 0;
SYSCTL_INT(_kern, OID_AUTO, sniff_enable, CTLFLAG_RW, &sniff_enable, 0 , "");
SYSCTL_INT(_kern, OID_AUTO, sniff_target, CTLFLAG_RW, &sniff_target, 0 , "");
SYSCTL_INT(_debug, OID_AUTO, clock_debug2, CTLFLAG_RW, &clock_debug2, 0 , "");

__read_mostly long pseudo_ticks = 1;		/* existential timed locks */

static int
sysctl_cputime(SYSCTL_HANDLER_ARGS)
{
	int cpu, error = 0;
	int root_error;
	size_t size = sizeof(struct kinfo_cputime);
	struct kinfo_cputime tmp;

	/*
	 * NOTE: For security reasons, only root can sniff %rip
	 */
	root_error = caps_priv_check_self(SYSCAP_RESTRICTEDROOT);

	for (cpu = 0; cpu < ncpus; ++cpu) {
		tmp = cputime_percpu[cpu];
		if (root_error == 0) {
			tmp.cp_sample_pc =
				(int64_t)globaldata_find(cpu)->gd_sample_pc;
			tmp.cp_sample_sp =
				(int64_t)globaldata_find(cpu)->gd_sample_sp;
		}
		if ((error = SYSCTL_OUT(req, &tmp, size)) != 0)
			break;
	}

	if (root_error == 0) {
		if (sniff_enable) {
			int n = sniff_target;
			if (n < 0)
				smp_sniff();
			else if (n < ncpus)
				cpu_sniff(n);
		}
	}

	return (error);
}
SYSCTL_PROC(_kern, OID_AUTO, cputime, (CTLTYPE_OPAQUE|CTLFLAG_RD), 0, 0,
	sysctl_cputime, "S,kinfo_cputime", "CPU time statistics");

static int
sysctl_cp_time(SYSCTL_HANDLER_ARGS)
{
	long cpu_states[CPUSTATES] = {0};
	int cpu, error = 0;
	size_t size = sizeof(cpu_states);

	for (cpu = 0; cpu < ncpus; ++cpu) {
		cpu_states[CP_USER] += cputime_percpu[cpu].cp_user;
		cpu_states[CP_NICE] += cputime_percpu[cpu].cp_nice;
		cpu_states[CP_SYS] += cputime_percpu[cpu].cp_sys;
		cpu_states[CP_INTR] += cputime_percpu[cpu].cp_intr;
		cpu_states[CP_IDLE] += cputime_percpu[cpu].cp_idle;
	}

	error = SYSCTL_OUT(req, cpu_states, size);

	return (error);
}

SYSCTL_PROC(_kern, OID_AUTO, cp_time, (CTLTYPE_LONG|CTLFLAG_RD), 0, 0,
    sysctl_cp_time, "LU", "CPU time statistics");

static int
sysctl_cp_times(SYSCTL_HANDLER_ARGS)
{
	long cpu_states[CPUSTATES] = {0};
	int cpu, error;
	size_t size = sizeof(cpu_states);

	for (error = 0, cpu = 0; error == 0 && cpu < ncpus; ++cpu) {
		cpu_states[CP_USER] = cputime_percpu[cpu].cp_user;
		cpu_states[CP_NICE] = cputime_percpu[cpu].cp_nice;
		cpu_states[CP_SYS] = cputime_percpu[cpu].cp_sys;
		cpu_states[CP_INTR] = cputime_percpu[cpu].cp_intr;
		cpu_states[CP_IDLE] = cputime_percpu[cpu].cp_idle;
		error = SYSCTL_OUT(req, cpu_states, size);
	}

	return (error);
}

SYSCTL_PROC(_kern, OID_AUTO, cp_times, (CTLTYPE_LONG|CTLFLAG_RD), 0, 0,
    sysctl_cp_times, "LU", "per-CPU time statistics");

/*
 * boottime is used to calculate the 'real' uptime.  Do not confuse this with
 * microuptime().  microtime() is not drift compensated.  The real uptime
 * with compensation is nanotime() - bootime.  boottime is recalculated
 * whenever the real time is set based on the compensated elapsed time
 * in seconds (gd->gd_time_seconds).
 *
 * The gd_time_seconds and gd_cpuclock_base fields remain fairly monotonic.
 * Slight adjustments to gd_cpuclock_base are made to phase-lock it to
 * the real time.
 *
 * WARNING! time_second can backstep on time corrections. Also, unlike
 *          time_second, time_uptime is not a "real" time_t (seconds
 *          since the Epoch) but seconds since booting.
 */
__read_mostly struct timespec boottime;	/* boot time (realtime) for ref only */
__read_mostly struct timespec ticktime0;/* updated every tick */
__read_mostly struct timespec ticktime2;/* updated every tick */
__read_mostly int ticktime_update;
__read_mostly time_t time_second;	/* read-only 'passive' rt in seconds */
__read_mostly time_t time_uptime;	/* read-only 'passive' ut in seconds */

/*
 * basetime is used to calculate the compensated real time of day.  The
 * basetime can be modified on a per-tick basis by the adjtime(),
 * ntp_adjtime(), and sysctl-based time correction APIs.
 *
 * Note that frequency corrections can also be made by adjusting
 * gd_cpuclock_base.
 *
 * basetime is a tail-chasing FIFO, updated only by cpu #0.  The FIFO is
 * used on both SMP and UP systems to avoid MP races between cpu's and
 * interrupt races on UP systems.
 */
struct hardtime {
	__uint32_t time_second;
	sysclock_t cpuclock_base;
};

#define BASETIME_ARYSIZE	16
#define BASETIME_ARYMASK	(BASETIME_ARYSIZE - 1)
static struct timespec basetime[BASETIME_ARYSIZE];
static struct hardtime hardtime[BASETIME_ARYSIZE];
static volatile int basetime_index;

static int
sysctl_get_basetime(SYSCTL_HANDLER_ARGS)
{
	struct timespec *bt;
	int error;
	int index;

	/*
	 * Because basetime data and index may be updated by another cpu,
	 * a load fence is required to ensure that the data we read has
	 * not been speculatively read relative to a possibly updated index.
	 */
	index = basetime_index;
	cpu_lfence();
	bt = &basetime[index];
	error = SYSCTL_OUT(req, bt, sizeof(*bt));
	return (error);
}

SYSCTL_STRUCT(_kern, KERN_BOOTTIME, boottime, CTLFLAG_RD,
    &boottime, timespec, "System boottime");
SYSCTL_PROC(_kern, OID_AUTO, basetime, CTLTYPE_STRUCT|CTLFLAG_RD, 0, 0,
    sysctl_get_basetime, "S,timespec", "System basetime");

static void hardclock(systimer_t info, int, struct intrframe *frame);
static void statclock(systimer_t info, int, struct intrframe *frame);
static void schedclock(systimer_t info, int, struct intrframe *frame);
static void getnanotime_nbt(struct timespec *nbt, struct timespec *tsp);

/*
 * Use __read_mostly for ticks and sched_ticks because these variables are
 * used all over the kernel and only updated once per tick.
 */
__read_mostly sbintime_t sbticks;	/* system master ticks at hz (64bit) */
__read_mostly int ticks;		/* system master ticks at hz */
__read_mostly int sched_ticks;		/* global schedule clock ticks */
__read_mostly int clocks_running;	/* tsleep/timeout clocks operational */
int64_t	nsec_adj;		/* ntpd per-tick adjustment in nsec << 32 */
int64_t	nsec_acc;		/* accumulator */

/* NTPD time correction fields */
int64_t	ntp_tick_permanent;	/* per-tick adjustment in nsec << 32 */
int64_t	ntp_tick_acc;		/* accumulator for per-tick adjustment */
int64_t	ntp_delta;		/* one-time correction in nsec */
int64_t ntp_big_delta = 1000000000;
int32_t	ntp_tick_delta;		/* current adjustment rate */
int32_t	ntp_default_tick_delta;	/* adjustment rate for ntp_delta */
time_t	ntp_leap_second;	/* time of next leap second */
int	ntp_leap_insert;	/* whether to insert or remove a second */
struct spinlock ntp_spin;

/*
 * Finish initializing clock frequencies and start all clocks running.
 */
/* ARGSUSED*/
static void
initclocks(void *dummy)
{
	/*psratio = profhz / stathz;*/
	spin_init(&ntp_spin, "ntp");
	initclocks_pcpu();
	clocks_running = 1;
	if (kpmap) {
	    kpmap->tsc_freq = tsc_frequency;
	    kpmap->tick_freq = hz;
	}
}

/*
 * Called on a per-cpu basis from the idle thread bootstrap on each cpu
 * during SMP initialization.
 *
 * This routine is called concurrently during low-level SMP initialization
 * and may not block in any way.  Meaning, among other things, we can't
 * acquire any tokens.
 */
void
initclocks_pcpu(void)
{
	struct globaldata *gd = mycpu;

	crit_enter();
	if (gd->gd_cpuid == 0) {
	    gd->gd_time_seconds = 1;
	    gd->gd_cpuclock_base = sys_cputimer->count();
	    hardtime[0].time_second = gd->gd_time_seconds;
	    hardtime[0].cpuclock_base = gd->gd_cpuclock_base;
	} else {
	    gd->gd_time_seconds = globaldata_find(0)->gd_time_seconds;
	    gd->gd_cpuclock_base = globaldata_find(0)->gd_cpuclock_base;
	}

	systimer_intr_enable();

	crit_exit();
}

/*
 * Called on a 10-second interval after the system is operational.
 * Return the collection data for USERPCT and install the data for
 * SYSTPCT and IDLEPCT.
 */
static
uint64_t
collect_cputime_callback(int n)
{
	static long cpu_base[CPUSTATES];
	long cpu_states[CPUSTATES];
	long total;
	long acc;
	long lsb;

	bzero(cpu_states, sizeof(cpu_states));
	for (n = 0; n < ncpus; ++n) {
		cpu_states[CP_USER] += cputime_percpu[n].cp_user;
		cpu_states[CP_NICE] += cputime_percpu[n].cp_nice;
		cpu_states[CP_SYS] += cputime_percpu[n].cp_sys;
		cpu_states[CP_INTR] += cputime_percpu[n].cp_intr;
		cpu_states[CP_IDLE] += cputime_percpu[n].cp_idle;
	}

	acc = 0;
	for (n = 0; n < CPUSTATES; ++n) {
		total = cpu_states[n] - cpu_base[n];
		cpu_base[n] = cpu_states[n];
		cpu_states[n] = total;
		acc += total;
	}
	if (acc == 0)		/* prevent degenerate divide by 0 */
		acc = 1;
	lsb = acc / (10000 * 2);
	kcollect_setvalue(KCOLLECT_SYSTPCT,
			  (cpu_states[CP_SYS] + lsb) * 10000 / acc);
	kcollect_setvalue(KCOLLECT_IDLEPCT,
			  (cpu_states[CP_IDLE] + lsb) * 10000 / acc);
	kcollect_setvalue(KCOLLECT_INTRPCT,
			  (cpu_states[CP_INTR] + lsb) * 10000 / acc);
	return((cpu_states[CP_USER] + cpu_states[CP_NICE] + lsb) * 10000 / acc);
}

/*
 * This routine is called on just the BSP, just after SMP initialization
 * completes to * finish initializing any clocks that might contend/block
 * (e.g. like on a token).  We can't do this in initclocks_pcpu() because
 * that function is called from the idle thread bootstrap for each cpu and
 * not allowed to block at all.
 */
static
void
initclocks_other(void *dummy)
{
	struct globaldata *ogd = mycpu;
	struct globaldata *gd;
	int n;

	for (n = 0; n < ncpus; ++n) {
		lwkt_setcpu_self(globaldata_find(n));
		gd = mycpu;

		/*
		 * Use a non-queued periodic systimer to prevent multiple
		 * ticks from building up if the sysclock jumps forward
		 * (8254 gets reset).  The sysclock will never jump backwards.
		 * Our time sync is based on the actual sysclock, not the
		 * ticks count.
		 *
		 * Install statclock before hardclock to prevent statclock
		 * from misinterpreting gd_flags for tick assignment when
		 * they overlap.  Also offset the statclock by half of
		 * its interval to try to avoid being coincident with
		 * callouts.
		 */
		systimer_init_periodic_flags(&gd->gd_statclock, statclock,
					  NULL, stathz,
					  SYSTF_MSSYNC | SYSTF_FIRST |
					  SYSTF_OFFSET50 | SYSTF_OFFSETCPU);
		systimer_init_periodic_flags(&gd->gd_hardclock, hardclock,
					  NULL, hz,
					  SYSTF_MSSYNC | SYSTF_OFFSETCPU);
	}
	lwkt_setcpu_self(ogd);

	/*
	 * Regular data collection
	 */
	kcollect_register(KCOLLECT_USERPCT, "user", collect_cputime_callback,
			  KCOLLECT_SCALE(KCOLLECT_USERPCT_FORMAT, 0));
	kcollect_register(KCOLLECT_SYSTPCT, "syst", NULL,
			  KCOLLECT_SCALE(KCOLLECT_SYSTPCT_FORMAT, 0));
	kcollect_register(KCOLLECT_IDLEPCT, "idle", NULL,
			  KCOLLECT_SCALE(KCOLLECT_IDLEPCT_FORMAT, 0));
}
SYSINIT(clocks2, SI_BOOT2_POST_SMP, SI_ORDER_ANY, initclocks_other, NULL);

/*
 * This method is called on just the BSP, after all the usched implementations
 * are initialized. This avoids races between usched initialization functions
 * and usched_schedulerclock().
 */
static
void
initclocks_usched(void *dummy)
{
	struct globaldata *ogd = mycpu;
	struct globaldata *gd;
	int n;

	for (n = 0; n < ncpus; ++n) {
		lwkt_setcpu_self(globaldata_find(n));
		gd = mycpu;

		/* XXX correct the frequency for scheduler / estcpu tests */
		systimer_init_periodic_flags(&gd->gd_schedclock, schedclock,
					  NULL, ESTCPUFREQ,
					  SYSTF_MSSYNC | SYSTF_OFFSETCPU);
	}
	lwkt_setcpu_self(ogd);
}
SYSINIT(clocks3, SI_BOOT2_USCHED, SI_ORDER_ANY, initclocks_usched, NULL);

/*
 * This sets the current real time of day.  Timespecs are in seconds and
 * nanoseconds.  We do not mess with gd_time_seconds and gd_cpuclock_base,
 * instead we adjust basetime so basetime + gd_* results in the current
 * time of day.  This way the gd_* fields are guaranteed to represent
 * a monotonically increasing 'uptime' value.
 *
 * When set_timeofday() is called from userland, the system call forces it
 * onto cpu #0 since only cpu #0 can update basetime_index.
 */
void
set_timeofday(struct timespec *ts)
{
	struct timespec *nbt;
	int ni;

	/*
	 * XXX SMP / non-atomic basetime updates
	 */
	crit_enter();
	ni = (basetime_index + 1) & BASETIME_ARYMASK;
	cpu_lfence();
	nbt = &basetime[ni];
	nanouptime(nbt);
	nbt->tv_sec = ts->tv_sec - nbt->tv_sec;
	nbt->tv_nsec = ts->tv_nsec - nbt->tv_nsec;
	if (nbt->tv_nsec < 0) {
	    nbt->tv_nsec += 1000000000;
	    --nbt->tv_sec;
	}

	/*
	 * Note that basetime diverges from boottime as the clock drift is
	 * compensated for, so we cannot do away with boottime.  When setting
	 * the absolute time of day the drift is 0 (for an instant) and we
	 * can simply assign boottime to basetime.
	 *
	 * Note that nanouptime() is based on gd_time_seconds which is drift
	 * compensated up to a point (it is guaranteed to remain monotonically
	 * increasing).  gd_time_seconds is thus our best uptime guess and
	 * suitable for use in the boottime calculation.  It is already taken
	 * into account in the basetime calculation above.
	 */
	spin_lock(&ntp_spin);
	boottime.tv_sec = nbt->tv_sec;
	ntp_delta = 0;

	/*
	 * We now have a new basetime, make sure all other cpus have it,
	 * then update the index.
	 */
	cpu_sfence();
	basetime_index = ni;
	spin_unlock(&ntp_spin);

	crit_exit();
}

/*
 * Each cpu has its own hardclock, but we only increment ticks and softticks
 * on cpu #0.
 *
 * NOTE! systimer! the MP lock might not be held here.  We can only safely
 * manipulate objects owned by the current cpu.
 */
static void
hardclock(systimer_t info, int in_ipi, struct intrframe *frame)
{
	sysclock_t cputicks;
	struct proc *p;
	struct globaldata *gd = mycpu;

	if ((gd->gd_reqflags & RQF_IPIQ) == 0 && lwkt_need_ipiq_process(gd)) {
		/* Defer to doreti on passive IPIQ processing */
		need_ipiq();
	}

	/*
	 * We update the compensation base to calculate fine-grained time
	 * from the sys_cputimer on a per-cpu basis in order to avoid
	 * having to mess around with locks.  sys_cputimer is assumed to
	 * be consistent across all cpus.  CPU N copies the base state from
	 * CPU 0 using the same FIFO trick that we use for basetime (so we
	 * don't catch a CPU 0 update in the middle).
	 *
	 * Note that we never allow info->time (aka gd->gd_hardclock.time)
	 * to reverse index gd_cpuclock_base, but that it is possible for
	 * it to temporarily get behind in the seconds if something in the
	 * system locks interrupts for a long period of time.  Since periodic
	 * timers count events, though everything should resynch again
	 * immediately.
	 */
	if (gd->gd_cpuid == 0) {
		int ni;

		cputicks = info->time - gd->gd_cpuclock_base;
		if (cputicks >= sys_cputimer->freq) {
			cputicks /= sys_cputimer->freq;
			if (cputicks != 0 && cputicks != 1)
				kprintf("Warning: hardclock missed > 1 sec\n");
			gd->gd_time_seconds += cputicks;
			gd->gd_cpuclock_base += sys_cputimer->freq * cputicks;
			/* uncorrected monotonic 1-sec gran */
			time_uptime += cputicks;
		}
		ni = (basetime_index + 1) & BASETIME_ARYMASK;
		hardtime[ni].time_second = gd->gd_time_seconds;
		hardtime[ni].cpuclock_base = gd->gd_cpuclock_base;
	} else {
		int ni;

		ni = basetime_index;
		cpu_lfence();
		gd->gd_time_seconds = hardtime[ni].time_second;
		gd->gd_cpuclock_base = hardtime[ni].cpuclock_base;
	}

	/*
	 * The system-wide ticks counter and NTP related timedelta/tickdelta
	 * adjustments only occur on cpu #0.  NTP adjustments are accomplished
	 * by updating basetime.
	 */
	if (gd->gd_cpuid == 0) {
	    struct timespec *nbt;
	    struct timespec nts;
	    int leap;
	    int ni;

	    /*
	     * Update system-wide ticks
	     */
	    ++ticks;
	    ++sbticks;

	    /*
	     * Update system-wide ticktime for getnanotime() and getmicrotime()
	     */
	    nanotime(&nts);
	    atomic_add_int_nonlocked(&ticktime_update, 1);
	    cpu_sfence();
	    if (ticktime_update & 2)
		ticktime2 = nts;
	    else
		ticktime0 = nts;
	    cpu_sfence();
	    atomic_add_int_nonlocked(&ticktime_update, 1);

#if 0
	    if (tco->tc_poll_pps)
		tco->tc_poll_pps(tco);
#endif

	    /*
	     * Calculate the new basetime index.  We are in a critical section
	     * on cpu #0 and can safely play with basetime_index.  Start
	     * with the current basetime and then make adjustments.
	     */
	    ni = (basetime_index + 1) & BASETIME_ARYMASK;
	    nbt = &basetime[ni];
	    *nbt = basetime[basetime_index];

	    /*
	     * ntp adjustments only occur on cpu 0 and are protected by
	     * ntp_spin.  This spinlock virtually never conflicts.
	     */
	    spin_lock(&ntp_spin);

	    /*
	     * Apply adjtime corrections.  (adjtime() API)
	     *
	     * adjtime() only runs on cpu #0 so our critical section is
	     * sufficient to access these variables.
	     */
	    if (ntp_delta != 0) {
		nbt->tv_nsec += ntp_tick_delta;
		ntp_delta -= ntp_tick_delta;
		if ((ntp_delta > 0 && ntp_delta < ntp_tick_delta) ||
		    (ntp_delta < 0 && ntp_delta > ntp_tick_delta)) {
			ntp_tick_delta = ntp_delta;
		}
	    }

	    /*
	     * Apply permanent frequency corrections.  (sysctl API)
	     */
	    if (ntp_tick_permanent != 0) {
		ntp_tick_acc += ntp_tick_permanent;
		if (ntp_tick_acc >= (1LL << 32)) {
		    nbt->tv_nsec += ntp_tick_acc >> 32;
		    ntp_tick_acc -= (ntp_tick_acc >> 32) << 32;
		} else if (ntp_tick_acc <= -(1LL << 32)) {
		    /* Negate ntp_tick_acc to avoid shifting the sign bit. */
		    nbt->tv_nsec -= (-ntp_tick_acc) >> 32;
		    ntp_tick_acc += ((-ntp_tick_acc) >> 32) << 32;
		}
	    }

	    if (nbt->tv_nsec >= 1000000000) {
		    nbt->tv_sec++;
		    nbt->tv_nsec -= 1000000000;
	    } else if (nbt->tv_nsec < 0) {
		    nbt->tv_sec--;
		    nbt->tv_nsec += 1000000000;
	    }

	    /*
	     * Another per-tick compensation.  (for ntp_adjtime() API)
	     */
	    if (nsec_adj != 0) {
		nsec_acc += nsec_adj;
		if (nsec_acc >= 0x100000000LL) {
		    nbt->tv_nsec += nsec_acc >> 32;
		    nsec_acc = (nsec_acc & 0xFFFFFFFFLL);
		} else if (nsec_acc <= -0x100000000LL) {
		    nbt->tv_nsec -= -nsec_acc >> 32;
		    nsec_acc = -(-nsec_acc & 0xFFFFFFFFLL);
		}
		if (nbt->tv_nsec >= 1000000000) {
		    nbt->tv_nsec -= 1000000000;
		    ++nbt->tv_sec;
		} else if (nbt->tv_nsec < 0) {
		    nbt->tv_nsec += 1000000000;
		    --nbt->tv_sec;
		}
	    }
	    spin_unlock(&ntp_spin);

	    /************************************************************
	     *			LEAP SECOND CORRECTION			*
	     ************************************************************
	     *
	     * Taking into account all the corrections made above, figure
	     * out the new real time.  If the seconds field has changed
	     * then apply any pending leap-second corrections.
	     */
	    getnanotime_nbt(nbt, &nts);

	    if (time_second != nts.tv_sec) {
		/*
		 * Apply leap second (sysctl API).  Adjust nts for changes
		 * so we do not have to call getnanotime_nbt again.
		 */
		if (ntp_leap_second) {
		    if (ntp_leap_second == nts.tv_sec) {
			if (ntp_leap_insert) {
			    nbt->tv_sec++;
			    nts.tv_sec++;
			} else {
			    nbt->tv_sec--;
			    nts.tv_sec--;
			}
			ntp_leap_second--;
		    }
		}

		/*
		 * Apply leap second (ntp_adjtime() API), calculate a new
		 * nsec_adj field.  ntp_update_second() returns nsec_adj
		 * as a per-second value but we need it as a per-tick value.
		 */
		leap = ntp_update_second(time_second, &nsec_adj);
		nsec_adj /= hz;
		nbt->tv_sec += leap;
		nts.tv_sec += leap;

		/*
		 * Update the time_second 'approximate time' global.
		 */
		time_second = nts.tv_sec;

		/*
		 * Clear the IPC hint for the currently running thread once
		 * per second, allowing us to disconnect the hint from a
		 * thread which may no longer care.
		 */
		curthread->td_wakefromcpu = -1;
	    }

	    /*
	     * Finally, our new basetime is ready to go live!
	     */
	    cpu_sfence();
	    basetime_index = ni;

	    /*
	     * Update kpmap on each tick.  TS updates are integrated with
	     * fences and upticks allowing userland to read the data
	     * deterministically.
	     */
	    if (kpmap) {
		int w;

		w = (kpmap->upticks + 1) & 1;
		getnanouptime(&kpmap->ts_uptime[w]);
		getnanotime(&kpmap->ts_realtime[w]);
		cpu_sfence();
		++kpmap->upticks;
		cpu_sfence();
	    }

	    /*
	     * Handle exislock pseudo_ticks.  We make things as simple as
	     * possible for the critical path arming code by adding a little
	     * complication here.
	     *
	     * When we find that all cores have been armed, we increment
	     * pseudo_ticks and disarm all the cores.
	     */
	    {
		globaldata_t gd;
		int n;

		for (n = 0; n < ncpus; ++n) {
		    gd = globaldata_find(n);
		    if (gd->gd_exisarmed == 0)
			break;
		}

		if (n == ncpus) {
		    for (n = 0; n < ncpus; ++n) {
			gd = globaldata_find(n);
			gd->gd_exisarmed = 0;
		    }
		    ++pseudo_ticks;
		}
	    }
	}

	/*
	 * lwkt thread scheduler fair queueing
	 */
	lwkt_schedulerclock(curthread);

	/*
	 * Cycle the existential lock system on odd ticks in order to re-arm
	 * our cpu (in case the cpu is idle or nobody is using any exis locks).
	 */
	if (ticks & 1) {
		exis_hold_gd(gd);
		exis_drop_gd(gd);
	}

	/*
	 * softticks are handled for all cpus
	 */
	hardclock_softtick(gd);

	/*
	 * Rollup accumulated vmstats, copy-back for critical path checks.
	 */
	vmstats_rollup_cpu(gd);
	vfscache_rollup_cpu(gd);
	mycpu->gd_vmstats = vmstats;

	/*
	 * ITimer handling is per-tick, per-cpu.
	 *
	 * We must acquire the per-process token in order for ksignal()
	 * to be non-blocking.  For the moment this requires an AST fault,
	 * the ksignal() cannot be safely issued from this hard interrupt.
	 *
	 * XXX Even the trytoken here isn't right, and itimer operation in
	 *     a multi threaded environment is going to be weird at the
	 *     very least.
	 */
	if ((p = curproc) != NULL && lwkt_trytoken(&p->p_token)) {
		crit_enter_hard();
		if (p->p_upmap)
			++p->p_upmap->runticks;

		if (frame && CLKF_USERMODE(frame) &&
		    timevalisset(&p->p_timer[ITIMER_VIRTUAL].it_value) &&
		    itimerdecr(&p->p_timer[ITIMER_VIRTUAL], ustick) == 0) {
			p->p_flags |= P_SIGVTALRM;
			need_user_resched();
		}
		if (timevalisset(&p->p_timer[ITIMER_PROF].it_value) &&
		    itimerdecr(&p->p_timer[ITIMER_PROF], ustick) == 0) {
			p->p_flags |= P_SIGPROF;
			need_user_resched();
		}
		crit_exit_hard();
		lwkt_reltoken(&p->p_token);
	}
	setdelayed();
}

/*
 * The statistics clock typically runs at a 125Hz rate, and is intended
 * to be frequency offset from the hardclock (typ 100Hz).  It is per-cpu.
 *
 * NOTE! systimer! the MP lock might not be held here.  We can only safely
 * manipulate objects owned by the current cpu.
 *
 * The stats clock is responsible for grabbing a profiling sample.
 * Most of the statistics are only used by user-level statistics programs.
 * The main exceptions are p->p_uticks, p->p_sticks, p->p_iticks, and
 * p->p_estcpu.
 *
 * Like the other clocks, the stat clock is called from what is effectively
 * a fast interrupt, so the context should be the thread/process that got
 * interrupted.
 */
static void
statclock(systimer_t info, int in_ipi, struct intrframe *frame)
{
	globaldata_t gd = mycpu;
	thread_t td;
	struct proc *p;
	int bump;
	sysclock_t cv;
	sysclock_t scv;

	/*
	 * How big was our timeslice relative to the last time?  Calculate
	 * in microseconds.
	 *
	 * NOTE: Use of microuptime() is typically MPSAFE, but usually not
	 *	 during early boot.  Just use the systimer count to be nice
	 *	 to e.g. qemu.  The systimer has a better chance of being
	 *	 MPSAFE at early boot.
	 */
	cv = sys_cputimer->count();
	scv = gd->statint.gd_statcv;
	if (scv == 0) {
		bump = 1;
	} else {
		bump = muldivu64(sys_cputimer->freq64_usec,
				 (cv - scv), 1L << 32);
		if (bump < 0)
			bump = 0;
		if (bump > 1000000)
			bump = 1000000;
	}
	gd->statint.gd_statcv = cv;

#if 0
	stv = &gd->gd_stattv;
	if (stv->tv_sec == 0) {
	    bump = 1;
	} else {
	    bump = tv.tv_usec - stv->tv_usec +
		(tv.tv_sec - stv->tv_sec) * 1000000;
	    if (bump < 0)
		bump = 0;
	    if (bump > 1000000)
		bump = 1000000;
	}
	*stv = tv;
#endif

	td = curthread;
	p = td->td_proc;

	/*
	 * If this is an interrupt thread used for the clock interrupt, adjust
	 * td to the thread it is preempting.  If a frame is available, it will
	 * be related to the thread being preempted.
	 */
	if ((td->td_flags & TDF_CLKTHREAD) && td->td_preempted)
		td = td->td_preempted;

	if (frame && CLKF_USERMODE(frame)) {
		/*
		 * Came from userland, handle user time and deal with
		 * possible process.
		 */
		if (p && (p->p_flags & P_PROFIL))
			addupc_intr(p, CLKF_PC(frame), 1);
		td->td_uticks += bump;

		/*
		 * Charge the time as appropriate
		 */
		if (p && p->p_nice > NZERO)
			cpu_time.cp_nice += bump;
		else
			cpu_time.cp_user += bump;
	} else {
		int intr_nest = gd->gd_intr_nesting_level;

		if (in_ipi) {
			/*
			 * IPI processing code will bump gd_intr_nesting_level
			 * up by one, which breaks following CLKF_INTR testing,
			 * so we subtract it by one here.
			 */
			--intr_nest;
		}

		/*
		 * Came from kernel mode, so we were:
		 * - handling an interrupt,
		 * - doing syscall or trap work on behalf of the current
		 *   user process, or
		 * - spinning in the idle loop.
		 * Whichever it is, charge the time as appropriate.
		 * Note that we charge interrupts to the current process,
		 * regardless of whether they are ``for'' that process,
		 * so that we know how much of its real time was spent
		 * in ``non-process'' (i.e., interrupt) work.
		 *
		 * XXX assume system if frame is NULL.  A NULL frame
		 * can occur if ipi processing is done from a crit_exit().
		 */
		if ((frame && CLKF_INTR(intr_nest)) ||
		    cpu_interrupt_running(td)) {
			/*
			 * If we interrupted an interrupt thread, well,
			 * count it as interrupt time.
			 */
			td->td_iticks += bump;
#ifdef DEBUG_PCTRACK
			if (frame)
				do_pctrack(frame, PCTRACK_INT);
#endif
			cpu_time.cp_intr += bump;
		} else if (gd->gd_flags & GDF_VIRTUSER) {
			/*
			 * The vkernel doesn't do a good job providing trap
			 * frames that we can test.  If the GDF_VIRTUSER
			 * flag is set we probably interrupted user mode.
			 */
			td->td_uticks += bump;

			/*
			 * Charge the time as appropriate
			 */
			if (p && p->p_nice > NZERO)
				cpu_time.cp_nice += bump;
			else
				cpu_time.cp_user += bump;
		} else {
			if (clock_debug2 > 0) {
				--clock_debug2;
				kprintf("statclock preempt %s (%p %p)\n", td->td_comm, td, &gd->gd_idlethread);
			}
			td->td_sticks += bump;
			if (td == &gd->gd_idlethread) {
				/*
				 * We want to count token contention as
				 * system time.  When token contention occurs
				 * the cpu may only be outside its critical
				 * section while switching through the idle
				 * thread.  In this situation, various flags
				 * will be set in gd_reqflags.
				 *
				 * INTPEND is not necessarily useful because
				 * it will be set if the clock interrupt
				 * happens to be on an interrupt thread, the
				 * cpu_interrupt_running() call does a better
				 * job so we've already handled it.
				 */
				if (gd->gd_reqflags &
				    (RQF_IDLECHECK_WK_MASK & ~RQF_INTPEND)) {
					cpu_time.cp_sys += bump;
				} else {
					cpu_time.cp_idle += bump;
				}
			} else {
				/*
				 * System thread was running.
				 */
#ifdef DEBUG_PCTRACK
				if (frame)
					do_pctrack(frame, PCTRACK_SYS);
#endif
				cpu_time.cp_sys += bump;
			}
		}
	}
}

#ifdef DEBUG_PCTRACK
/*
 * Sample the PC when in the kernel or in an interrupt.  User code can
 * retrieve the information and generate a histogram or other output.
 */

static void
do_pctrack(struct intrframe *frame, int which)
{
	struct kinfo_pctrack *pctrack;

	pctrack = &cputime_pctrack[mycpu->gd_cpuid][which];
	pctrack->pc_array[pctrack->pc_index & PCTRACK_ARYMASK] =
		(void *)CLKF_PC(frame);
	++pctrack->pc_index;
}

static int
sysctl_pctrack(SYSCTL_HANDLER_ARGS)
{
	struct kinfo_pcheader head;
	int error;
	int cpu;
	int ntrack;

	head.pc_ntrack = PCTRACK_SIZE;
	head.pc_arysize = PCTRACK_ARYSIZE;

	if ((error = SYSCTL_OUT(req, &head, sizeof(head))) != 0)
		return (error);

	for (cpu = 0; cpu < ncpus; ++cpu) {
		for (ntrack = 0; ntrack < PCTRACK_SIZE; ++ntrack) {
			error = SYSCTL_OUT(req, &cputime_pctrack[cpu][ntrack],
					   sizeof(struct kinfo_pctrack));
			if (error)
				break;
		}
		if (error)
			break;
	}
	return (error);
}
SYSCTL_PROC(_kern, OID_AUTO, pctrack, (CTLTYPE_OPAQUE|CTLFLAG_RD), 0, 0,
	sysctl_pctrack, "S,kinfo_pcheader", "CPU PC tracking");

#endif

/*
 * The scheduler clock typically runs at a 50Hz rate.  NOTE! systimer,
 * the MP lock might not be held.  We can safely manipulate parts of curproc
 * but that's about it.
 *
 * Each cpu has its own scheduler clock.
 */
static void
schedclock(systimer_t info, int in_ipi __unused, struct intrframe *frame)
{
	struct lwp *lp;
	struct rusage *ru;
	struct vmspace *vm;
	long rss;

	if ((lp = lwkt_preempted_proc()) != NULL) {
		/*
		 * Account for cpu time used and hit the scheduler.  Note
		 * that this call MUST BE MP SAFE, and the BGL IS NOT HELD
		 * HERE.
		 */
		++lp->lwp_cpticks;
		usched_schedulerclock(lp, info->periodic, info->time);
	} else {
		usched_schedulerclock(NULL, info->periodic, info->time);
	}
	if ((lp = curthread->td_lwp) != NULL) {
		/*
		 * Update resource usage integrals and maximums.
		 */
		if ((ru = &lp->lwp_proc->p_ru) &&
		    (vm = lp->lwp_proc->p_vmspace) != NULL) {
			ru->ru_ixrss += pgtok(btoc(vm->vm_tsize));
			ru->ru_idrss += pgtok(btoc(vm->vm_dsize));
			ru->ru_isrss += pgtok(btoc(vm->vm_ssize));
			if (lwkt_trytoken(&vm->vm_map.token)) {
				rss = pgtok(vmspace_resident_count(vm));
				if (ru->ru_maxrss < rss)
					ru->ru_maxrss = rss;
				lwkt_reltoken(&vm->vm_map.token);
			}
		}
	}
	/* Increment the global sched_ticks */
	if (mycpu->gd_cpuid == 0)
		++sched_ticks;
}

/*
 * Compute number of ticks for the specified amount of time.  The
 * return value is intended to be used in a clock interrupt timed
 * operation and guaranteed to meet or exceed the requested time.
 * If the representation overflows, return INT_MAX.  The minimum return
 * value is 1 ticks and the function will average the calculation up.
 * If any value greater then 0 microseconds is supplied, a value
 * of at least 2 will be returned to ensure that a near-term clock
 * interrupt does not cause the timeout to occur (degenerately) early.
 *
 * Note that limit checks must take into account microseconds, which is
 * done simply by using the smaller signed long maximum instead of
 * the unsigned long maximum.
 *
 * If ints have 32 bits, then the maximum value for any timeout in
 * 10ms ticks is 248 days.
 */
int
tvtohz_high(struct timeval *tv)
{
	int ticks;
	long sec, usec;

	sec = tv->tv_sec;
	usec = tv->tv_usec;
	if (usec < 0) {
		sec--;
		usec += 1000000;
	}
	if (sec < 0) {
#ifdef DIAGNOSTIC
		if (usec > 0) {
			sec++;
			usec -= 1000000;
		}
		kprintf("tvtohz_high: negative time difference "
			"%ld sec %ld usec\n",
			sec, usec);
#endif
		ticks = 1;
	} else if (sec <= INT_MAX / hz) {
		ticks = (int)(sec * hz + howmany((u_long)usec, ustick)) + 1;
	} else {
		ticks = INT_MAX;
	}
	return (ticks);
}

int
tstohz_high(struct timespec *ts)
{
	int ticks;
	long sec, nsec;

	sec = ts->tv_sec;
	nsec = ts->tv_nsec;
	if (nsec < 0) {
		sec--;
		nsec += 1000000000;
	}
	if (sec < 0) {
#ifdef DIAGNOSTIC
		if (nsec > 0) {
			sec++;
			nsec -= 1000000000;
		}
		kprintf("tstohz_high: negative time difference "
			"%ld sec %ld nsec\n",
			sec, nsec);
#endif
		ticks = 1;
	} else if (sec <= INT_MAX / hz) {
		ticks = (int)(sec * hz + howmany((u_long)nsec, nstick)) + 1;
	} else {
		ticks = INT_MAX;
	}
	return (ticks);
}


/*
 * Compute number of ticks for the specified amount of time, erroring on
 * the side of it being too low to ensure that sleeping the returned number
 * of ticks will not result in a late return.
 *
 * The supplied timeval may not be negative and should be normalized.  A
 * return value of 0 is possible if the timeval converts to less then
 * 1 tick.
 *
 * If ints have 32 bits, then the maximum value for any timeout in
 * 10ms ticks is 248 days.
 */
int
tvtohz_low(struct timeval *tv)
{
	int ticks;
	long sec;

	sec = tv->tv_sec;
	if (sec <= INT_MAX / hz)
		ticks = (int)(sec * hz + (u_long)tv->tv_usec / ustick);
	else
		ticks = INT_MAX;
	return (ticks);
}

int
tstohz_low(struct timespec *ts)
{
	int ticks;
	long sec;

	sec = ts->tv_sec;
	if (sec <= INT_MAX / hz)
		ticks = (int)(sec * hz + (u_long)ts->tv_nsec / nstick);
	else
		ticks = INT_MAX;
	return (ticks);
}

/*
 * Start profiling on a process.
 *
 * Caller must hold p->p_token();
 *
 * Kernel profiling passes proc0 which never exits and hence
 * keeps the profile clock running constantly.
 */
void
startprofclock(struct proc *p)
{
	if ((p->p_flags & P_PROFIL) == 0) {
		p->p_flags |= P_PROFIL;
#if 0	/* XXX */
		if (++profprocs == 1 && stathz != 0) {
			crit_enter();
			psdiv = psratio;
			setstatclockrate(profhz);
			crit_exit();
		}
#endif
	}
}

/*
 * Stop profiling on a process.
 *
 * caller must hold p->p_token
 */
void
stopprofclock(struct proc *p)
{
	if (p->p_flags & P_PROFIL) {
		p->p_flags &= ~P_PROFIL;
#if 0	/* XXX */
		if (--profprocs == 0 && stathz != 0) {
			crit_enter();
			psdiv = 1;
			setstatclockrate(stathz);
			crit_exit();
		}
#endif
	}
}

/*
 * Return information about system clocks.
 */
static int
sysctl_kern_clockrate(SYSCTL_HANDLER_ARGS)
{
	struct kinfo_clockinfo clkinfo;
	/*
	 * Construct clockinfo structure.
	 */
	clkinfo.ci_hz = hz;
	clkinfo.ci_tick = ustick;
	clkinfo.ci_tickadj = ntp_default_tick_delta / 1000;
	clkinfo.ci_profhz = profhz;
	clkinfo.ci_stathz = stathz ? stathz : hz;
	return (sysctl_handle_opaque(oidp, &clkinfo, sizeof clkinfo, req));
}

SYSCTL_PROC(_kern, KERN_CLOCKRATE, clockrate, CTLTYPE_STRUCT|CTLFLAG_RD,
	0, 0, sysctl_kern_clockrate, "S,clockinfo","");

/*
 * We have eight functions for looking at the clock, four for
 * microseconds and four for nanoseconds.  For each there is fast
 * but less precise version "get{nano|micro}[up]time" which will
 * return a time which is up to 1/HZ previous to the call, whereas
 * the raw version "{nano|micro}[up]time" will return a timestamp
 * which is as precise as possible.  The "up" variants return the
 * time relative to system boot, these are well suited for time
 * interval measurements.
 *
 * Each cpu independently maintains the current time of day, so all
 * we need to do to protect ourselves from changes is to do a loop
 * check on the seconds field changing out from under us.
 *
 * The system timer maintains a 32 bit count and due to various issues
 * it is possible for the calculated delta to occasionally exceed
 * sys_cputimer->freq.  If this occurs the sys_cputimer->freq64_nsec
 * multiplication can easily overflow, so we deal with the case.  For
 * uniformity we deal with the case in the usec case too.
 *
 * All the [get][micro,nano][time,uptime]() routines are MPSAFE.
 *
 * NEW CODE (!)
 *
 *	cpu 0 now maintains global ticktimes and an update counter.  The
 *	getnanotime() and getmicrotime() routines use these globals.
 */
void
getmicrouptime(struct timeval *tvp)
{
	struct globaldata *gd = mycpu;
	sysclock_t delta;

	do {
		tvp->tv_sec = gd->gd_time_seconds;
		delta = gd->gd_hardclock.time - gd->gd_cpuclock_base;
	} while (tvp->tv_sec != gd->gd_time_seconds);

	if (delta >= sys_cputimer->freq) {
		tvp->tv_sec += delta / sys_cputimer->freq;
		delta %= sys_cputimer->freq;
	}
	tvp->tv_usec = muldivu64(sys_cputimer->freq64_usec, delta, 1L << 32);
	if (tvp->tv_usec >= 1000000) {
		tvp->tv_usec -= 1000000;
		++tvp->tv_sec;
	}
}

void
getnanouptime(struct timespec *tsp)
{
	struct globaldata *gd = mycpu;
	sysclock_t delta;

	do {
		tsp->tv_sec = gd->gd_time_seconds;
		delta = gd->gd_hardclock.time - gd->gd_cpuclock_base;
	} while (tsp->tv_sec != gd->gd_time_seconds);

	if (delta >= sys_cputimer->freq) {
		tsp->tv_sec += delta / sys_cputimer->freq;
		delta %= sys_cputimer->freq;
	}
	tsp->tv_nsec = muldivu64(sys_cputimer->freq64_nsec, delta, 1L << 32);
}

void
microuptime(struct timeval *tvp)
{
	struct globaldata *gd = mycpu;
	sysclock_t delta;

	do {
		tvp->tv_sec = gd->gd_time_seconds;
		delta = sys_cputimer->count() - gd->gd_cpuclock_base;
	} while (tvp->tv_sec != gd->gd_time_seconds);

	if (delta >= sys_cputimer->freq) {
		tvp->tv_sec += delta / sys_cputimer->freq;
		delta %= sys_cputimer->freq;
	}
	tvp->tv_usec = muldivu64(sys_cputimer->freq64_usec, delta, 1L << 32);
}

void
nanouptime(struct timespec *tsp)
{
	struct globaldata *gd = mycpu;
	sysclock_t delta;

	do {
		tsp->tv_sec = gd->gd_time_seconds;
		delta = sys_cputimer->count() - gd->gd_cpuclock_base;
	} while (tsp->tv_sec != gd->gd_time_seconds);

	if (delta >= sys_cputimer->freq) {
		tsp->tv_sec += delta / sys_cputimer->freq;
		delta %= sys_cputimer->freq;
	}
	tsp->tv_nsec = muldivu64(sys_cputimer->freq64_nsec, delta, 1L << 32);
}

/*
 * realtime routines
 */
void
getmicrotime(struct timeval *tvp)
{
	struct timespec ts;
	int counter;

	do {
		counter = *(volatile int *)&ticktime_update;
		cpu_lfence();
		switch(counter & 3) {
		case 0:			/* ticktime2 completed update */
			ts = ticktime2;
			break;
		case 1:			/* ticktime0 update in progress */
			ts = ticktime2;
			break;
		case 2:			/* ticktime0 completed update */
			ts = ticktime0;
			break;
		case 3:			/* ticktime2 update in progress */
			ts = ticktime0;
			break;
		}
		cpu_lfence();
	} while (counter != *(volatile int *)&ticktime_update);
	tvp->tv_sec = ts.tv_sec;
	tvp->tv_usec = ts.tv_nsec / 1000;
}

void
getnanotime(struct timespec *tsp)
{
	struct timespec ts;
	int counter;

	do {
		counter = *(volatile int *)&ticktime_update;
		cpu_lfence();
		switch(counter & 3) {
		case 0:			/* ticktime2 completed update */
			ts = ticktime2;
			break;
		case 1:			/* ticktime0 update in progress */
			ts = ticktime2;
			break;
		case 2:			/* ticktime0 completed update */
			ts = ticktime0;
			break;
		case 3:			/* ticktime2 update in progress */
			ts = ticktime0;
			break;
		}
		cpu_lfence();
	} while (counter != *(volatile int *)&ticktime_update);
	*tsp = ts;
}

static void
getnanotime_nbt(struct timespec *nbt, struct timespec *tsp)
{
	struct globaldata *gd = mycpu;
	sysclock_t delta;

	do {
		tsp->tv_sec = gd->gd_time_seconds;
		delta = gd->gd_hardclock.time - gd->gd_cpuclock_base;
	} while (tsp->tv_sec != gd->gd_time_seconds);

	if (delta >= sys_cputimer->freq) {
		tsp->tv_sec += delta / sys_cputimer->freq;
		delta %= sys_cputimer->freq;
	}
	tsp->tv_nsec = muldivu64(sys_cputimer->freq64_nsec, delta, 1L << 32);

	tsp->tv_sec += nbt->tv_sec;
	tsp->tv_nsec += nbt->tv_nsec;
	while (tsp->tv_nsec >= 1000000000) {
		tsp->tv_nsec -= 1000000000;
		++tsp->tv_sec;
	}
}


void
microtime(struct timeval *tvp)
{
	struct globaldata *gd = mycpu;
	struct timespec *bt;
	sysclock_t delta;

	do {
		tvp->tv_sec = gd->gd_time_seconds;
		delta = sys_cputimer->count() - gd->gd_cpuclock_base;
	} while (tvp->tv_sec != gd->gd_time_seconds);

	if (delta >= sys_cputimer->freq) {
		tvp->tv_sec += delta / sys_cputimer->freq;
		delta %= sys_cputimer->freq;
	}
	tvp->tv_usec = muldivu64(sys_cputimer->freq64_usec, delta, 1L << 32);

	bt = &basetime[basetime_index];
	cpu_lfence();
	tvp->tv_sec += bt->tv_sec;
	tvp->tv_usec += bt->tv_nsec / 1000;
	while (tvp->tv_usec >= 1000000) {
		tvp->tv_usec -= 1000000;
		++tvp->tv_sec;
	}
}

void
nanotime(struct timespec *tsp)
{
	struct globaldata *gd = mycpu;
	struct timespec *bt;
	sysclock_t delta;

	do {
		tsp->tv_sec = gd->gd_time_seconds;
		delta = sys_cputimer->count() - gd->gd_cpuclock_base;
	} while (tsp->tv_sec != gd->gd_time_seconds);

	if (delta >= sys_cputimer->freq) {
		tsp->tv_sec += delta / sys_cputimer->freq;
		delta %= sys_cputimer->freq;
	}
	tsp->tv_nsec = muldivu64(sys_cputimer->freq64_nsec, delta, 1L << 32);

	bt = &basetime[basetime_index];
	cpu_lfence();
	tsp->tv_sec += bt->tv_sec;
	tsp->tv_nsec += bt->tv_nsec;
	while (tsp->tv_nsec >= 1000000000) {
		tsp->tv_nsec -= 1000000000;
		++tsp->tv_sec;
	}
}

/*
 * Get an approximate time_t.  It does not have to be accurate.  This
 * function is called only from KTR and can be called with the system in
 * any state so do not use a critical section or other complex operation
 * here.
 *
 * NOTE: This is not exactly synchronized with real time.  To do that we
 *	 would have to do what microtime does and check for a nanoseconds
 *	 overflow.
 */
time_t
get_approximate_time_t(void)
{
	struct globaldata *gd = mycpu;
	struct timespec *bt;

	bt = &basetime[basetime_index];
	return(gd->gd_time_seconds + bt->tv_sec);
}

static int
pps_fetch_timeout(struct timespec *timeout, struct pps_state *pps)
{
	int to, err;
	pps_seq_t *ap, *cp;
	pps_seq_t a, c;

	to = INT_MAX;
	if (timeout->tv_sec > -1)
		to = tstohz_low(timeout);

	ap = &pps->ppsinfo.assert_sequence;
	cp = &pps->ppsinfo.clear_sequence;
	a = atomic_load_acq_int(ap);
	c = atomic_load_acq_int(cp);

	while (a == atomic_load_acq_int(ap) && c == atomic_load_acq_int(cp)) {
		err = tsleep(pps, PCATCH, "ppsfch", to);
		if (err == EWOULDBLOCK) {
			if (timeout->tv_sec < 0)
				continue;
			return (ETIMEDOUT);
		}
		if (err != 0)
			return (err);
	}

	return (0);
}

int
pps_ioctl(u_long cmd, caddr_t data, struct pps_state *pps)
{
	pps_params_t *app;
	struct pps_fetch_args *fapi;
#ifdef PPS_SYNC
	struct pps_kcbind_args *kapi;
#endif
	int err;

	switch (cmd) {
	case PPS_IOC_CREATE:
		return (0);
	case PPS_IOC_DESTROY:
		return (0);
	case PPS_IOC_SETPARAMS:
		app = (pps_params_t *)data;
		if (app->mode & ~pps->ppscap)
			return (EINVAL);
		pps->ppsparam = *app;
		return (0);
	case PPS_IOC_GETPARAMS:
		app = (pps_params_t *)data;
		*app = pps->ppsparam;
		app->api_version = PPS_API_VERS_1;
		return (0);
	case PPS_IOC_GETCAP:
		*(int*)data = pps->ppscap;
		return (0);
	case PPS_IOC_FETCH:
		fapi = (struct pps_fetch_args *)data;
		if (fapi->tsformat && fapi->tsformat != PPS_TSFMT_TSPEC)
			return (EINVAL);
		if (fapi->timeout.tv_sec != 0 || fapi->timeout.tv_nsec != 0) {
			err = pps_fetch_timeout(&fapi->timeout, pps);
			if (err != 0)
				return (err);
		}
		pps->ppsinfo.current_mode = pps->ppsparam.mode;
		fapi->pps_info_buf = pps->ppsinfo;
		return (0);
	case PPS_IOC_KCBIND:
#ifdef PPS_SYNC
		kapi = (struct pps_kcbind_args *)data;
		/* XXX Only root should be able to do this */
		if (kapi->tsformat && kapi->tsformat != PPS_TSFMT_TSPEC)
			return (EINVAL);
		if (kapi->kernel_consumer != PPS_KC_HARDPPS)
			return (EINVAL);
		if (kapi->edge & ~pps->ppscap)
			return (EINVAL);
		pps->kcmode = kapi->edge;
		return (0);
#else
		return (EOPNOTSUPP);
#endif
	default:
		return (ENOTTY);
	}
}

void
pps_init(struct pps_state *pps)
{
	pps->ppscap |= PPS_TSFMT_TSPEC | PPS_CANWAIT;
	if (pps->ppscap & PPS_CAPTUREASSERT)
		pps->ppscap |= PPS_OFFSETASSERT;
	if (pps->ppscap & PPS_CAPTURECLEAR)
		pps->ppscap |= PPS_OFFSETCLEAR;
}

void
pps_event(struct pps_state *pps, sysclock_t count, int event)
{
	struct globaldata *gd;
	struct timespec *tsp;
	struct timespec *osp;
	struct timespec *bt;
	struct timespec ts;
	sysclock_t *pcount;
#ifdef PPS_SYNC
	sysclock_t tcount;
#endif
	sysclock_t delta;
	pps_seq_t *pseq;
	int foff;
#ifdef PPS_SYNC
	int fhard;
#endif
	int ni;

	gd = mycpu;

	/* Things would be easier with arrays... */
	if (event == PPS_CAPTUREASSERT) {
		tsp = &pps->ppsinfo.assert_timestamp;
		osp = &pps->ppsparam.assert_offset;
		foff = pps->ppsparam.mode & PPS_OFFSETASSERT;
#ifdef PPS_SYNC
		fhard = pps->kcmode & PPS_CAPTUREASSERT;
#endif
		pcount = &pps->ppscount[0];
		pseq = &pps->ppsinfo.assert_sequence;
	} else {
		tsp = &pps->ppsinfo.clear_timestamp;
		osp = &pps->ppsparam.clear_offset;
		foff = pps->ppsparam.mode & PPS_OFFSETCLEAR;
#ifdef PPS_SYNC
		fhard = pps->kcmode & PPS_CAPTURECLEAR;
#endif
		pcount = &pps->ppscount[1];
		pseq = &pps->ppsinfo.clear_sequence;
	}

	/* Nothing really happened */
	if (*pcount == count)
		return;

	*pcount = count;

	do {
		ts.tv_sec = gd->gd_time_seconds;
		delta = count - gd->gd_cpuclock_base;
	} while (ts.tv_sec != gd->gd_time_seconds);

	if (delta >= sys_cputimer->freq) {
		ts.tv_sec += delta / sys_cputimer->freq;
		delta %= sys_cputimer->freq;
	}
	ts.tv_nsec = muldivu64(sys_cputimer->freq64_nsec, delta, 1L << 32);
	ni = basetime_index;
	cpu_lfence();
	bt = &basetime[ni];
	ts.tv_sec += bt->tv_sec;
	ts.tv_nsec += bt->tv_nsec;
	while (ts.tv_nsec >= 1000000000) {
		ts.tv_nsec -= 1000000000;
		++ts.tv_sec;
	}

	atomic_add_rel_int(pseq, 1);
	*tsp = ts;

	if (foff) {
		timespecadd(tsp, osp, tsp);
		if (tsp->tv_nsec < 0) {
			tsp->tv_nsec += 1000000000;
			tsp->tv_sec -= 1;
		}
	}
#ifdef PPS_SYNC
	if (fhard) {
		/* magic, at its best... */
		tcount = count - pps->ppscount[2];
		pps->ppscount[2] = count;
		if (tcount >= sys_cputimer->freq) {
			delta = (1000000000 * (tcount / sys_cputimer->freq) +
				 sys_cputimer->freq64_nsec *
				 (tcount % sys_cputimer->freq)) >> 32;
		} else {
			delta = muldivu64(sys_cputimer->freq64_nsec,
					  tcount, 1L << 32);
		}
		hardpps(tsp, delta);
	}
#endif
	wakeup(pps);
}

/*
 * Return the tsc target value for a delay of (ns).
 *
 * Returns -1 if the TSC is not supported.
 */
tsc_uclock_t
tsc_get_target(int ns)
{
#if defined(_RDTSC_SUPPORTED_)
	if (cpu_feature & CPUID_TSC) {
		return (rdtsc() + tsc_frequency * ns / (int64_t)1000000000);
	}
#endif
	return(-1);
}

/*
 * Compare the tsc against the passed target
 *
 * Returns +1 if the target has been reached
 * Returns  0 if the target has not yet been reached
 * Returns -1 if the TSC is not supported.
 *
 * Typical use:		while (tsc_test_target(target) == 0) { ...poll... }
 */
int
tsc_test_target(int64_t target)
{
#if defined(_RDTSC_SUPPORTED_)
	if (cpu_feature & CPUID_TSC) {
		if ((int64_t)(target - rdtsc()) <= 0)
			return(1);
		return(0);
	}
#endif
	return(-1);
}

/*
 * Delay the specified number of nanoseconds using the tsc.  This function
 * returns immediately if the TSC is not supported.  At least one cpu_pause()
 * will be issued.
 */
void
tsc_delay(int ns)
{
	int64_t clk;

	clk = tsc_get_target(ns);
	cpu_pause();
	cpu_pause();
	while (tsc_test_target(clk) == 0) {
		cpu_pause();
		cpu_pause();
		cpu_pause();
		cpu_pause();
	}
}
