/*
 * Copyright (c) 2003-2011 The DragonFly Project.  All rights reserved.
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
 * Copyright (c) Peter Wemm <peter@netplex.com.au> All rights reserved.
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef _SYS_GLOBALDATA_H_
#define _SYS_GLOBALDATA_H_

#if defined(_KERNEL) || defined(_KERNEL_STRUCTURES)

#ifndef _SYS_TIME_H_
#include <sys/time.h>		/* struct timeval */
#endif
#ifndef _SYS_VMMETER_H_
#include <sys/vmmeter.h>	/* struct vmmeter, pcpu vmstats adj */
#endif
#ifndef _SYS_THREAD_H_
#include <sys/thread.h>		/* struct thread */
#endif
#ifndef _SYS_SLABALLOC_H_
#include <sys/slaballoc.h>	/* SLGlobalData */
#endif
#ifndef _SYS_SYSTIMER_H_
#include <sys/systimer.h>	/* fine-grained system timers */
#endif
#ifndef _SYS_NCHSTATS_H_
#include <sys/nchstats.h>
#endif
#ifndef _SYS_SYSID_H_
#include <sys/sysid.h>		/* sysid_t */
#endif
#ifndef _SYS_CALLOUT_H_
#include <sys/callout.h>
#endif
#ifndef _SYS_INDEFINITE_H_
#include <sys/indefinite.h>
#endif
#ifndef _SYS_LOCK_H_
#include <sys/lock.h>
#endif
#include <machine/stdint.h>

/*
 * This structure maps out the global data that needs to be kept on a
 * per-cpu basis.  genassym uses this to generate offsets for the assembler
 * code.  The machine-dependant portions of this file can be found in
 * <machine/globaldata.h>, but only MD code should retrieve it.
 *
 * The SMP parts are setup in pmap.c and locore.s for the BSP, and
 * mp_machdep.c sets up the data for the AP's to "see" when they awake.
 * The reason for doing it via a struct is so that an array of pointers
 * to each CPU's data can be set up for things like "check curproc on all
 * other processors"
 *
 * NOTE! this structure needs to remain compatible between module accessors
 * and the kernel, so we can't throw in lots of #ifdef's.
 *
 * gd_reqflags serves serveral purposes, but it is primarily an interrupt
 * rollup flag used by the task switcher and spl mechanisms to decide that
 * further checks are necessary.  Interrupts are typically managed on a
 * per-processor basis at least until you leave a critical section, but
 * may then be scheduled to other cpus.
 *
 * gd_vme_avail and gd_vme_base cache free vm_map_entry structures for use
 * in various vm_map related operations.  gd_vme_avail is *NOT* a count of
 * the number of structures in the cache but is instead a count of the number
 * of unreserved structures in the cache.  See vm_map_entry_reserve().
 */

struct sysmsg;
struct tslpque;
struct privatespace;
struct vm_map_entry;
struct spinlock;
struct pipe;

struct globaldata {
	struct privatespace *gd_prvspace;	/* self-reference */
	struct thread	*gd_curthread;
	struct thread	*gd_freetd;		/* cache one free td */
	__uint32_t	gd_reqflags;		/* (see note above) */
	long		gd_flags;
	lwkt_queue	gd_tdallq;		/* all threads */
	lwkt_queue	gd_tdrunq;		/* runnable threads */
	__uint32_t	gd_cpuid;
	cpumask_t	gd_cpumask;		/* CPUMASK_ASSBIT(cpuid) */
	cpumask_t	gd_other_cpus;		/* mask of 'other' cpus */
	union {
		struct timeval	gd_stattv;
		sysclock_t	gd_statcv;
	} statint;
	int		gd_intr_nesting_level;	/* hard code, intrs, ipis */
	struct vmmeter	gd_cnt;
	struct vmtotal	gd_vmtotal;
	cpumask_t	gd_ipimask;		/* pending ipis from cpus */
	struct lwkt_ipiq *gd_ipiq;		/* array[ncpu] of ipiq's */
	struct lwkt_ipiq gd_cpusyncq;		/* ipiq for cpu synchro */
	u_int		gd_npoll;		/* ipiq synchronization */
	int		gd_tdrunqcount;

	/* temporary mess to retain structural compatibility for now */
	union {
		struct {
			struct {
				int	gd_exisarmed;
			} __cachealign;
		};
		long	gd_reserved02B[200];	/* used to be struct thread */
	};
	struct thread	gd_idlethread;
	SLGlobalData	gd_slab;		/* slab allocator */
	KMGlobalData	gd_kmslab;		/* kmalloc slab cache */
	int		gd_trap_nesting_level;	/* track traps */
	int		gd_vme_avail;		/* vm_map_entry reservation */
	struct vm_map_entry *gd_vme_base;	/* vm_map_entry reservation */
	struct systimerq gd_systimerq;		/* per-cpu system timers */
	int		gd_syst_nest;
	struct systimer gd_hardclock;		/* scheduler periodic */
	struct systimer gd_statclock;		/* statistics periodic */
	struct systimer gd_schedclock;		/* scheduler periodic */
	volatile __uint32_t gd_time_seconds;	/* uptime in seconds */
	volatile sysclock_t gd_cpuclock_base;	/* cpuclock relative base */

	struct pipe	*gd_pipeq;		/* cache pipe structures */
	struct nchstats	*gd_nchstats;		/* namecache effectiveness */
	int		gd_pipeqcount;		/* number of structures */
	sysid_t		gd_sysid_alloc;		/* allocate unique sysid */

	struct tslpque	*gd_tsleep_hash;	/* tsleep/wakeup support */
	long		gd_processing_ipiq;
	int		gd_spinlocks;		/* Exclusive spinlocks held */
	struct systimer	*gd_systimer_inprog;	/* in-progress systimer */
	int		gd_timer_running;
	u_int		gd_idle_repeat;		/* repeated switches to idle */
	int		gd_quick_color;		/* page-coloring helper */
	int		gd_cachedvnodes;	/* accum across all cpus */
	int		gd_rand_incr;		/* random pcpu incrementor */
	int		gd_activevnodes;	/* accum across all cpus */
	int		gd_inactivevnodes;	/* accum across all cpus */
	int		gd_ireserved[2];
	const char	*gd_infomsg;		/* debugging */
	struct lwkt_tokref gd_handoff;		/* hand-off tokref */
	void		*gd_delayed_wakeup[2];
	void		*gd_sample_pc;		/* sample program ctr/tr */
	uint64_t	gd_anoninum;		/* anonymous inode (pipes) */
	uint64_t	gd_forkid;		/* per-cpu unique inc ncpus */
	void		*gd_sample_sp;		/* sample stack pointer */
	uint64_t	gd_cpumask_simple;
	uint64_t	gd_cpumask_offset;
	struct vmstats	gd_vmstats;		/* pcpu local copy of vmstats */
	struct vmstats	gd_vmstats_adj;		/* pcpu adj for vmstats */
	struct callout	gd_loadav_callout;	/* loadavg calc */
	struct callout	gd_schedcpu_callout;	/* scheduler/stats */
	indefinite_info_t gd_indefinite;	/* scheduler cpu-bound */
	uint32_t	gd_loadav_nrunnable;	/* pcpu lwps nrunnable */
	uint32_t	gd_reserved32[1];
	struct lock	gd_sysctllock;		/* sysctl topology lock */
	uintptr_t	gd_debug1;
	uintptr_t	gd_debug2;
	long		gd_exislockcnt;
	void		*gd_preserved[1];	/* future fields */
	/* extended by <machine/globaldata.h> */
};

typedef struct globaldata *globaldata_t;

#define RQB_IPIQ		0	/* 0001 */
#define RQB_INTPEND		1	/* 0002 */
#define RQB_AST_OWEUPC		2	/* 0004 */
#define RQB_AST_SIGNAL		3	/* 0008 */
#define RQB_AST_USER_RESCHED	4	/* 0010 */
#define RQB_AST_LWKT_RESCHED	5	/* 0020 */
#define RQB_UNUSED6		6	/* 0040 */
#define RQB_TIMER		7	/* 0080 */
#define RQB_RUNNING		8	/* 0100 */
#define RQB_SPINNING		9	/* 0200 */
#define RQB_QUICKRET		10	/* 0400 */
#define RQB_KQUEUE		11	/* 0800 (only used by vkernel) */
#define RQB_XINVLTLB		12	/* 1000 (HVM interlock) */

#define RQF_IPIQ		(1 << RQB_IPIQ)
#define RQF_INTPEND		(1 << RQB_INTPEND)
#define RQF_TIMER		(1 << RQB_TIMER)
#define RQF_AST_OWEUPC		(1 << RQB_AST_OWEUPC)
#define RQF_AST_SIGNAL		(1 << RQB_AST_SIGNAL)
#define RQF_AST_USER_RESCHED	(1 << RQB_AST_USER_RESCHED)
#define RQF_AST_LWKT_RESCHED	(1 << RQB_AST_LWKT_RESCHED)
#define RQF_RUNNING		(1 << RQB_RUNNING)
#define RQF_SPINNING		(1 << RQB_SPINNING)
#define RQF_QUICKRET		(1 << RQB_QUICKRET)
#define RQF_KQUEUE		(1 << RQB_KQUEUE)
#define RQF_XINVLTLB		(1 << RQB_XINVLTLB)

#define RQF_AST_MASK		(RQF_AST_OWEUPC|RQF_AST_SIGNAL|\
				 RQF_AST_USER_RESCHED|RQF_AST_LWKT_RESCHED)
#define RQF_IDLECHECK_MASK	(RQF_IPIQ|RQF_INTPEND|RQF_TIMER|RQF_KQUEUE)
#define RQF_IDLECHECK_WK_MASK	(RQF_IDLECHECK_MASK|RQF_AST_LWKT_RESCHED)
#define RQF_SCHED_MASK		(RQF_IDLECHECK_MASK|RQF_AST_USER_RESCHED|\
				 RQF_AST_LWKT_RESCHED)
#define RQF_HVM_MASK		(RQF_IDLECHECK_MASK|RQF_AST_MASK|RQF_XINVLTLB)

/*
 * globaldata flags
 */
#define GDF_KPRINTF		0x0001	/* kprintf() reentrancy */
#define GDF_VIRTUSER		0x0002	/* used by vmm & vkernel */

#endif

/*
 * MANUAL DEBUG CODE FOR DEBUGGING LOCKUPS
 */
#ifdef _KERNEL

#if 0

#define DEBUG_PUSH_INFO(msg)				\
	const char *save_infomsg;			\
	save_infomsg = mycpu->gd_infomsg;		\
	mycpu->gd_infomsg = msg				\

#define DEBUG_POP_INFO()	mycpu->gd_infomsg = save_infomsg

#else

#define DEBUG_PUSH_INFO(msg)
#define DEBUG_POP_INFO()

#endif

#endif

#ifdef _KERNEL
struct globaldata *globaldata_find(int cpu);
int is_globaldata_space(vm_offset_t saddr, vm_offset_t eaddr);
#endif

#endif
