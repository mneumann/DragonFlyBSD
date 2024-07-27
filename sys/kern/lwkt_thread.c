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
 */

/*
 * Each cpu in a system has its own self-contained light weight kernel
 * thread scheduler, which means that generally speaking we only need
 * to use a critical section to avoid problems.  Foreign thread
 * scheduling is queued via (async) IPIs.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/proc.h>
#include <sys/rtprio.h>
#include <sys/kinfo.h>
#include <sys/malloc.h>
#include <sys/queue.h>
#include <sys/sysctl.h>
#include <sys/kthread.h>
#include <machine/cpu.h>
#include <sys/lock.h>
#include <sys/spinlock.h>
#include <sys/ktr.h>
#include <sys/indefinite.h>

#include <sys/thread2.h>
#include <sys/spinlock2.h>
#include <sys/indefinite2.h>

#include <sys/dsched.h>

#include <vm/vm.h>
#include <vm/vm_param.h>
#include <vm/vm_kern.h>
#include <vm/vm_object.h>
#include <vm/vm_page.h>
#include <vm/vm_map.h>
#include <vm/vm_pager.h>
#include <vm/vm_extern.h>

#include <machine/stdarg.h>
#include <machine/smp.h>
#include <machine/clock.h>

#define LOOPMASK

#if !defined(KTR_CTXSW)
#define KTR_CTXSW KTR_ALL
#endif
KTR_INFO_MASTER(ctxsw);
KTR_INFO(KTR_CTXSW, ctxsw, sw, 0, "#cpu[%d].td = %p", int cpu, struct thread *td);
KTR_INFO(KTR_CTXSW, ctxsw, pre, 1, "#cpu[%d].td = %p", int cpu, struct thread *td);
KTR_INFO(KTR_CTXSW, ctxsw, newtd, 2, "#threads[%p].name = %s", struct thread *td, char *comm);
KTR_INFO(KTR_CTXSW, ctxsw, deadtd, 3, "#threads[%p].name = <dead>", struct thread *td);

static MALLOC_DEFINE(M_THREAD, "thread", "lwkt threads");
MALLOC_DEFINE(M_FPUCTX, "fpuctx", "kernel FPU contexts");

#ifdef	INVARIANTS
static int panic_on_cscount = 0;
#endif
#ifdef DEBUG_LWKT_THREAD
static int64_t switch_count = 0;
static int64_t preempt_hit = 0;
static int64_t preempt_miss = 0;
static int64_t preempt_weird = 0;
#endif
static int lwkt_use_spin_port;
__read_mostly static struct objcache *thread_cache;
int cpu_mwait_spin = 0;

static void lwkt_schedule_remote(void *arg, int arg2, struct intrframe *frame);
static void lwkt_setcpu_remote(void *arg);

/*
 * We can make all thread ports use the spin backend instead of the thread
 * backend.  This should only be set to debug the spin backend.
 */
TUNABLE_INT("lwkt.use_spin_port", &lwkt_use_spin_port);

#ifdef	INVARIANTS
SYSCTL_INT(_lwkt, OID_AUTO, panic_on_cscount, CTLFLAG_RW, &panic_on_cscount, 0,
    "Panic if attempting to switch lwkt's while mastering cpusync");
#endif
#ifdef DEBUG_LWKT_THREAD
SYSCTL_QUAD(_lwkt, OID_AUTO, switch_count, CTLFLAG_RW, &switch_count, 0,
    "Number of switched threads");
SYSCTL_QUAD(_lwkt, OID_AUTO, preempt_hit, CTLFLAG_RW, &preempt_hit, 0,
    "Successful preemption events");
SYSCTL_QUAD(_lwkt, OID_AUTO, preempt_miss, CTLFLAG_RW, &preempt_miss, 0,
    "Failed preemption events");
SYSCTL_QUAD(_lwkt, OID_AUTO, preempt_weird, CTLFLAG_RW, &preempt_weird, 0,
    "Number of preempted threads.");
#endif
extern int lwkt_sched_debug;
int lwkt_sched_debug = 0;
SYSCTL_INT(_lwkt, OID_AUTO, sched_debug, CTLFLAG_RW,
	&lwkt_sched_debug, 0, "Scheduler debug");
__read_mostly static u_int lwkt_spin_loops = 10;
SYSCTL_UINT(_lwkt, OID_AUTO, spin_loops, CTLFLAG_RW,
	&lwkt_spin_loops, 0, "Scheduler spin loops until sorted decon");
__read_mostly static int preempt_enable = 1;
SYSCTL_INT(_lwkt, OID_AUTO, preempt_enable, CTLFLAG_RW,
	&preempt_enable, 0, "Enable preemption");
static int lwkt_cache_threads = 0;
SYSCTL_INT(_lwkt, OID_AUTO, cache_threads, CTLFLAG_RD,
	&lwkt_cache_threads, 0, "thread+kstack cache");

/*
 * These helper procedures handle the runq, they can only be called from
 * within a critical section.
 *
 * WARNING!  Prior to SMP being brought up it is possible to enqueue and
 * dequeue threads belonging to other cpus, so be sure to use td->td_gd
 * instead of 'mycpu' when referencing the globaldata structure.   Once
 * SMP live enqueuing and dequeueing only occurs on the current cpu.
 */
static __inline
void
_lwkt_dequeue(thread_t td)
{
    if (td->td_flags & TDF_RUNQ) {
	struct globaldata *gd = td->td_gd;

	td->td_flags &= ~TDF_RUNQ;
	TAILQ_REMOVE(&gd->gd_tdrunq, td, td_threadq);
	--gd->gd_tdrunqcount;
	if (TAILQ_FIRST(&gd->gd_tdrunq) == NULL)
		atomic_clear_int(&gd->gd_reqflags, RQF_RUNNING);
    }
}

/*
 * Priority enqueue.
 *
 * There are a limited number of lwkt threads runnable since user
 * processes only schedule one at a time per cpu.  However, there can
 * be many user processes in kernel mode exiting from a tsleep() which
 * become runnable.
 *
 * We scan the queue in both directions to help deal with degenerate
 * situations when hundreds or thousands (or more) threads are runnable.
 *
 * NOTE: lwkt_schedulerclock() will force a round-robin based on td_pri and
 *	 will ignore user priority.  This is to ensure that user threads in
 *	 kernel mode get cpu at some point regardless of what the user
 *	 scheduler thinks.
 */
static __inline
void
_lwkt_enqueue(thread_t td)
{
    thread_t xtd;	/* forward scan */
    thread_t rtd;	/* reverse scan */

    if ((td->td_flags & (TDF_RUNQ|TDF_MIGRATING|TDF_BLOCKQ)) == 0) {
	struct globaldata *gd = td->td_gd;

	td->td_flags |= TDF_RUNQ;
	xtd = TAILQ_FIRST(&gd->gd_tdrunq);
	if (xtd == NULL) {
	    TAILQ_INSERT_TAIL(&gd->gd_tdrunq, td, td_threadq);
	    atomic_set_int(&gd->gd_reqflags, RQF_RUNNING);
	} else {
	    /*
	     * NOTE: td_upri - higher numbers more desirable, same sense
	     *	     as td_pri (typically reversed from lwp_upri).
	     *
	     *	     In the equal priority case we want the best selection
	     *	     at the beginning so the less desirable selections know
	     *	     that they have to setrunqueue/go-to-another-cpu, even
	     *	     though it means switching back to the 'best' selection.
	     *	     This also avoids degenerate situations when many threads
	     *	     are runnable or waking up at the same time.
	     *
	     *	     If upri matches exactly place at end/round-robin.
	     */
	    rtd = TAILQ_LAST(&gd->gd_tdrunq, lwkt_queue);

	    while (xtd &&
		   (xtd->td_pri > td->td_pri ||
		    (xtd->td_pri == td->td_pri &&
		     xtd->td_upri >= td->td_upri))) {
		xtd = TAILQ_NEXT(xtd, td_threadq);

		/*
		 * Doing a reverse scan at the same time is an optimization
		 * for the insert-closer-to-tail case that avoids having to
		 * scan the entire list.  This situation can occur when
		 * thousands of threads are woken up at the same time.
		 */
		if (rtd->td_pri > td->td_pri ||
		    (rtd->td_pri == td->td_pri &&
		    rtd->td_upri >= td->td_upri)) {
			TAILQ_INSERT_AFTER(&gd->gd_tdrunq, rtd, td, td_threadq);
			goto skip;
		}
		rtd = TAILQ_PREV(rtd, lwkt_queue, td_threadq);
	    }
	    if (xtd)
		TAILQ_INSERT_BEFORE(xtd, td, td_threadq);
	    else
		TAILQ_INSERT_TAIL(&gd->gd_tdrunq, td, td_threadq);
	}
skip:
	++gd->gd_tdrunqcount;

	/*
	 * Request a LWKT reschedule if we are now at the head of the queue.
	 */
	if (TAILQ_FIRST(&gd->gd_tdrunq) == td)
	    need_lwkt_resched();
    }
}

static boolean_t
_lwkt_thread_ctor(void *obj, void *privdata, int ocflags)
{
    struct thread *td = (struct thread *)obj;

    td->td_kstack = NULL;
    td->td_kstack_size = 0;
    td->td_flags = TDF_ALLOCATED_THREAD;
    td->td_mpflags = 0;
    return (1);
}

static void
_lwkt_thread_dtor(void *obj, void *privdata)
{
    struct thread *td = (struct thread *)obj;

    KASSERT(td->td_flags & TDF_ALLOCATED_THREAD,
	("_lwkt_thread_dtor: not allocated from objcache"));
    KASSERT((td->td_flags & TDF_ALLOCATED_STACK) && td->td_kstack &&
	    td->td_kstack_size > 0,
	("_lwkt_thread_dtor: corrupted stack"));
    kmem_free(kernel_map, (vm_offset_t)td->td_kstack, td->td_kstack_size);
    td->td_kstack = NULL;
    td->td_flags = 0;
}

/*
 * Initialize the lwkt s/system.
 *
 * Nominally cache up to 32 thread + kstack structures.  Cache more on
 * systems with a lot of cpu cores.
 */
static void
lwkt_init(void)
{
    TUNABLE_INT("lwkt.cache_threads", &lwkt_cache_threads);
    if (lwkt_cache_threads == 0) {
	lwkt_cache_threads = ncpus * 4;
	if (lwkt_cache_threads < 32)
	    lwkt_cache_threads = 32;
    }
    thread_cache = objcache_create_mbacked(
				M_THREAD, sizeof(struct thread),
				0, lwkt_cache_threads,
				_lwkt_thread_ctor, _lwkt_thread_dtor, NULL);
}
SYSINIT(lwkt_init, SI_BOOT2_LWKT_INIT, SI_ORDER_FIRST, lwkt_init, NULL);

/*
 * Schedule a thread to run.  As the current thread we can always safely
 * schedule ourselves, and a shortcut procedure is provided for that
 * function.
 *
 * (non-blocking, self contained on a per cpu basis)
 */
void
lwkt_schedule_self(thread_t td)
{
    KKASSERT((td->td_flags & TDF_MIGRATING) == 0);
    crit_enter_quick(td);
    KASSERT(td != &td->td_gd->gd_idlethread,
	    ("lwkt_schedule_self(): scheduling gd_idlethread is illegal!"));
    KKASSERT(td->td_lwp == NULL ||
	     (td->td_lwp->lwp_mpflags & LWP_MP_ONRUNQ) == 0);
    _lwkt_enqueue(td);
    crit_exit_quick(td);
}

/*
 * Deschedule a thread.
 *
 * (non-blocking, self contained on a per cpu basis)
 */
void
lwkt_deschedule_self(thread_t td)
{
    crit_enter_quick(td);
    _lwkt_dequeue(td);
    crit_exit_quick(td);
}

/*
 * LWKTs operate on a per-cpu basis
 *
 * WARNING!  Called from early boot, 'mycpu' may not work yet.
 */
void
lwkt_gdinit(struct globaldata *gd)
{
    TAILQ_INIT(&gd->gd_tdrunq);
    TAILQ_INIT(&gd->gd_tdallq);
    lockinit(&gd->gd_sysctllock, "sysctl", 0, LK_CANRECURSE);
}

/*
 * Create a new thread.  The thread must be associated with a process context
 * or LWKT start address before it can be scheduled.  If the target cpu is
 * -1 the thread will be created on the current cpu.
 *
 * If you intend to create a thread without a process context this function
 * does everything except load the startup and switcher function.
 */
thread_t
lwkt_alloc_thread(struct thread *td, int stksize, int cpu, int flags)
{
    static int cpu_rotator;
    globaldata_t gd = mycpu;
    void *stack;

    /*
     * If static thread storage is not supplied allocate a thread.  Reuse
     * a cached free thread if possible.  gd_freetd is used to keep an exiting
     * thread intact through the exit.
     */
    if (td == NULL) {
	crit_enter_gd(gd);
	if ((td = gd->gd_freetd) != NULL) {
	    KKASSERT((td->td_flags & (TDF_RUNNING|TDF_PREEMPT_LOCK|
				      TDF_RUNQ)) == 0);
	    gd->gd_freetd = NULL;
	} else {
	    td = objcache_get(thread_cache, M_WAITOK);
	    KKASSERT((td->td_flags & (TDF_RUNNING|TDF_PREEMPT_LOCK|
				      TDF_RUNQ)) == 0);
	}
	crit_exit_gd(gd);
    	KASSERT((td->td_flags &
		 (TDF_ALLOCATED_THREAD|TDF_RUNNING|TDF_PREEMPT_LOCK)) ==
		 TDF_ALLOCATED_THREAD,
		("lwkt_alloc_thread: corrupted td flags 0x%X", td->td_flags));
    	flags |= td->td_flags & (TDF_ALLOCATED_THREAD|TDF_ALLOCATED_STACK);
    }

    /*
     * Try to reuse cached stack.
     */
    if ((stack = td->td_kstack) != NULL && td->td_kstack_size != stksize) {
	if (flags & TDF_ALLOCATED_STACK) {
	    kmem_free(kernel_map, (vm_offset_t)stack, td->td_kstack_size);
	    stack = NULL;
	}
    }
    if (stack == NULL) {
	if (cpu < 0) {
		stack = (void *)kmem_alloc_stack(kernel_map, stksize, 0);
	} else {
		stack = (void *)kmem_alloc_stack(kernel_map, stksize,
						 KM_CPU(cpu));
	}
	flags |= TDF_ALLOCATED_STACK;
    }
    if (cpu < 0) {
	cpu = ++cpu_rotator;
	cpu_ccfence();
	cpu = (uint32_t)cpu % (uint32_t)ncpus;
    }
    lwkt_init_thread(td, stack, stksize, flags, globaldata_find(cpu));
    return(td);
}

/*
 * Initialize a preexisting thread structure.  This function is used by
 * lwkt_alloc_thread() and also used to initialize the per-cpu idlethread.
 *
 * All threads start out in a critical section at a priority of
 * TDPRI_KERN_DAEMON.  Higher level code will modify the priority as
 * appropriate.  This function may send an IPI message when the
 * requested cpu is not the current cpu and consequently gd_tdallq may
 * not be initialized synchronously from the point of view of the originating
 * cpu.
 *
 * NOTE! we have to be careful in regards to creating threads for other cpus
 * if SMP has not yet been activated.
 */
static void
lwkt_init_thread_remote(void *arg)
{
    thread_t td = arg;

    /*
     * Protected by critical section held by IPI dispatch
     */
    TAILQ_INSERT_TAIL(&td->td_gd->gd_tdallq, td, td_allq);
}

/*
 * lwkt core thread structural initialization.
 *
 * NOTE: All threads are initialized as mpsafe threads.
 */
void
lwkt_init_thread(thread_t td, void *stack, int stksize, int flags,
		struct globaldata *gd)
{
    globaldata_t mygd = mycpu;

    bzero(td, sizeof(struct thread));
    td->td_kstack = stack;
    td->td_kstack_size = stksize;
    td->td_flags = flags;
    td->td_mpflags = 0;
    td->td_type = TD_TYPE_GENERIC;
    td->td_gd = gd;
    td->td_pri = TDPRI_KERN_DAEMON;
    td->td_critcount = 1;
    td->td_toks_have = NULL;
    td->td_toks_stop = &td->td_toks_base;
    if (lwkt_use_spin_port || (flags & TDF_FORCE_SPINPORT)) {
	lwkt_initport_spin(&td->td_msgport, td,
	    (flags & TDF_FIXEDCPU) ? TRUE : FALSE);
    } else {
	lwkt_initport_thread(&td->td_msgport, td);
    }
    pmap_init_thread(td);

    /*
     * Normally initializing a thread for a remote cpu requires sending an
     * IPI.  However, the idlethread is setup before the other cpus are
     * activated so we have to treat it as a special case.  XXX manipulation
     * of gd_tdallq requires the BGL.
     */
    if (gd == mygd || td == &gd->gd_idlethread) {
	crit_enter_gd(mygd);
	TAILQ_INSERT_TAIL(&gd->gd_tdallq, td, td_allq);
	crit_exit_gd(mygd);
    } else {
	lwkt_send_ipiq(gd, lwkt_init_thread_remote, td);
    }
    dsched_enter_thread(td);
}

void
lwkt_set_comm(thread_t td, const char *ctl, ...)
{
    __va_list va;

    __va_start(va, ctl);
    kvsnprintf(td->td_comm, sizeof(td->td_comm), ctl, va);
    __va_end(va);
    KTR_LOG(ctxsw_newtd, td, td->td_comm);
}

/*
 * Prevent the thread from getting destroyed.  Note that unlike PHOLD/PRELE
 * this does not prevent the thread from migrating to another cpu so the
 * gd_tdallq state is not protected by this.
 */
void
lwkt_hold(thread_t td)
{
    atomic_add_int(&td->td_refs, 1);
}

void
lwkt_rele(thread_t td)
{
    KKASSERT(td->td_refs > 0);
    atomic_add_int(&td->td_refs, -1);
}

void
lwkt_free_thread(thread_t td)
{
    KKASSERT(td->td_refs == 0);
    KKASSERT((td->td_flags & (TDF_RUNNING | TDF_PREEMPT_LOCK |
			      TDF_RUNQ | TDF_TSLEEPQ | TDF_KERNELFP)) == 0);

    if (td->td_kfpuctx) {
	kfree(td->td_kfpuctx, M_FPUCTX);
	td->td_kfpuctx = NULL;
    }

    if (td->td_flags & TDF_ALLOCATED_THREAD) {
    	objcache_put(thread_cache, td);
    } else if (td->td_flags & TDF_ALLOCATED_STACK) {
	/* client-allocated struct with internally allocated stack */
	KASSERT(td->td_kstack && td->td_kstack_size > 0,
	    ("lwkt_free_thread: corrupted stack"));
	kmem_free(kernel_map, (vm_offset_t)td->td_kstack, td->td_kstack_size);
	td->td_kstack = NULL;
	td->td_kstack_size = 0;
    }

    KTR_LOG(ctxsw_deadtd, td);
}


/*
 * Switch to the next runnable lwkt.  If no LWKTs are runnable then
 * switch to the idlethread.  Switching must occur within a critical
 * section to avoid races with the scheduling queue.
 *
 * We always have full control over our cpu's run queue.  Other cpus
 * that wish to manipulate our queue must use the cpu_*msg() calls to
 * talk to our cpu, so a critical section is all that is needed and
 * the result is very, very fast thread switching.
 *
 * The LWKT scheduler uses a fixed priority model and round-robins at
 * each priority level.  User process scheduling is a totally
 * different beast and LWKT priorities should not be confused with
 * user process priorities.
 *
 * PREEMPTION NOTE: Preemption occurs via lwkt_preempt().  lwkt_switch()
 * is not called by the current thread in the preemption case, only when
 * the preempting thread blocks (in order to return to the original thread).
 *
 * SPECIAL NOTE ON SWITCH ATOMICY: Certain operations such as thread
 * migration and tsleep deschedule the current lwkt thread and call
 * lwkt_switch().  In particular, the target cpu of the migration fully
 * expects the thread to become non-runnable and can deadlock against
 * cpusync operations if we run any IPIs prior to switching the thread out.
 *
 * WE MUST BE VERY CAREFUL NOT TO RUN SPLZ DIRECTLY OR INDIRECTLY IF
 * THE CURRENT THREAD HAS BEEN DESCHEDULED!
 */
void
lwkt_switch(void)
{
    globaldata_t gd = mycpu;
    thread_t td = gd->gd_curthread;
    thread_t ntd;
    thread_t xtd;
    int upri;
#ifdef LOOPMASK
    uint64_t tsc_base = rdtsc();
#endif

    KKASSERT(gd->gd_processing_ipiq == 0);
    KKASSERT(td->td_flags & TDF_RUNNING);

    /*
     * Switching from within a 'fast' (non thread switched) interrupt or IPI
     * is illegal.  However, we may have to do it anyway if we hit a fatal
     * kernel trap or we have paniced.
     *
     * If this case occurs save and restore the interrupt nesting level.
     */
    if (gd->gd_intr_nesting_level) {
	int savegdnest;
	int savegdtrap;

	if (gd->gd_trap_nesting_level == 0 && panic_cpu_gd != mycpu) {
	    panic("lwkt_switch: Attempt to switch from a "
		  "fast interrupt, ipi, or hard code section, "
		  "td %p\n",
		  td);
	} else {
	    savegdnest = gd->gd_intr_nesting_level;
	    savegdtrap = gd->gd_trap_nesting_level;
	    gd->gd_intr_nesting_level = 0;
	    gd->gd_trap_nesting_level = 0;
	    if ((td->td_flags & TDF_PANICWARN) == 0) {
		td->td_flags |= TDF_PANICWARN;
		kprintf("Warning: thread switch from interrupt, IPI, "
			"or hard code section.\n"
			"thread %p (%s)\n", td, td->td_comm);
		print_backtrace(-1);
	    }
	    lwkt_switch();
	    gd->gd_intr_nesting_level = savegdnest;
	    gd->gd_trap_nesting_level = savegdtrap;
	    return;
	}
    }

    /*
     * Release our current user process designation if we are blocking
     * or if a user reschedule was requested.
     *
     * NOTE: This function is NOT called if we are switching into or
     *	     returning from a preemption.
     *
     * NOTE: Releasing our current user process designation may cause
     *	     it to be assigned to another thread, which in turn will
     *	     cause us to block in the usched acquire code when we attempt
     *	     to return to userland.
     *
     * NOTE: On SMP systems this can be very nasty when heavy token
     *	     contention is present so we want to be careful not to
     *	     release the designation gratuitously.
     */
    if (td->td_release &&
	(user_resched_wanted() || (td->td_flags & TDF_RUNQ) == 0)) {
	    td->td_release(td);
    }

    /*
     * Release all tokens.  Once we do this we must remain in the critical
     * section and cannot run IPIs or other interrupts until we switch away
     * because they may implode if they try to get a token using our thread
     * context.
     */
    crit_enter_gd(gd);
    if (TD_TOKS_HELD(td))
	    lwkt_relalltokens(td);

    /*
     * We had better not be holding any spin locks, but don't get into an
     * endless panic loop.
     */
    KASSERT(gd->gd_spinlocks == 0 || panicstr != NULL,
	    ("lwkt_switch: still holding %d exclusive spinlocks!",
	     gd->gd_spinlocks));

#ifdef	INVARIANTS
    if (td->td_cscount) {
	kprintf("Diagnostic: attempt to switch while mastering cpusync: %p\n",
		td);
	if (panic_on_cscount)
	    panic("switching while mastering cpusync");
    }
#endif

    /*
     * If we had preempted another thread on this cpu, resume the preempted
     * thread.  This occurs transparently, whether the preempted thread
     * was scheduled or not (it may have been preempted after descheduling
     * itself).
     *
     * We have to setup the MP lock for the original thread after backing
     * out the adjustment that was made to curthread when the original
     * was preempted.
     */
    if ((ntd = td->td_preempted) != NULL) {
	KKASSERT(ntd->td_flags & TDF_PREEMPT_LOCK);
	ntd->td_flags |= TDF_PREEMPT_DONE;
	ntd->td_contended = 0;		/* reset contended */

	/*
	 * The interrupt may have woken a thread up, we need to properly
	 * set the reschedule flag if the originally interrupted thread is
	 * at a lower priority.
	 *
	 * NOTE: The interrupt may not have descheduled ntd.
	 *
	 * NOTE: We do not reschedule if there are no threads on the runq.
	 *	 (ntd could be the idlethread).
	 */
	xtd = TAILQ_FIRST(&gd->gd_tdrunq);
	if (xtd && xtd != ntd)
	    need_lwkt_resched();
	goto havethread_preempted;
    }

    /*
     * Figure out switch target.  If we cannot switch to our desired target
     * look for a thread that we can switch to.
     *
     * NOTE! The limited spin loop and related parameters are extremely
     *	     important for system performance, particularly for pipes and
     *	     concurrent conflicting VM faults.
     */
    clear_lwkt_resched();
    ntd = TAILQ_FIRST(&gd->gd_tdrunq);

    if (ntd) {
	do {
	    if (TD_TOKS_NOT_HELD(ntd) ||
		lwkt_getalltokens(ntd, (ntd->td_contended > lwkt_spin_loops)))
	    {
		goto havethread;
	    }
	    ++ntd->td_contended;	/* overflow ok */
	    if (gd->gd_indefinite.type == 0)
		indefinite_init(&gd->gd_indefinite, NULL, NULL, 0, 't');
#ifdef LOOPMASK
	    if (tsc_frequency && rdtsc() - tsc_base > tsc_frequency) {
		    kprintf("lwkt_switch: WARNING, excessive token contention "
			    "cpu %d, %d sec, "
			    "td %p (%s)\n",
			    gd->gd_cpuid,
			    ntd->td_contended,
			    ntd,
			    ntd->td_comm);
		    tsc_base = rdtsc();
	    }
#endif
	} while (ntd->td_contended < (lwkt_spin_loops >> 1));
	upri = ntd->td_upri;

	/*
	 * Bleh, the thread we wanted to switch to has a contended token.
	 * See if we can switch to another thread.
	 *
	 * We generally don't want to do this because it represents a
	 * priority inversion, but contending tokens on the same cpu can
	 * cause real problems if we don't now that we have an exclusive
	 * priority mechanism over shared for tokens.
	 *
	 * The solution is to allow threads with pending tokens to compete
	 * for them (a lower priority thread will get less cpu once it
	 * returns from the kernel anyway).  If a thread does not have
	 * any contending tokens, we go by td_pri and upri.
	 */
	while ((ntd = TAILQ_NEXT(ntd, td_threadq)) != NULL) {
	    if (TD_TOKS_NOT_HELD(ntd) &&
		ntd->td_pri < TDPRI_KERN_LPSCHED && upri > ntd->td_upri) {
		    continue;
	    }
	    if (upri < ntd->td_upri)
		upri = ntd->td_upri;

	    /*
	     * Try this one.
	     */
	    if (TD_TOKS_NOT_HELD(ntd) ||
		lwkt_getalltokens(ntd, (ntd->td_contended > lwkt_spin_loops))) {
		    goto havethread;
	    }
	    ++ntd->td_contended;	/* overflow ok */
	}

	/*
	 * Fall through, switch to idle thread to get us out of the current
	 * context.  Since we were contended, prevent HLT by flagging a
	 * LWKT reschedule.
	 */
	need_lwkt_resched();
    }

    /*
     * We either contended on ntd or the runq is empty.  We must switch
     * through the idle thread to get out of the current context.
     */
    ntd = &gd->gd_idlethread;
    if (gd->gd_trap_nesting_level == 0 && panicstr == NULL)
	ASSERT_NO_TOKENS_HELD(ntd);
    cpu_time.cp_msg[0] = 0;
    goto haveidle;

havethread:
    /*
     * Clear gd_idle_repeat when doing a normal switch to a non-idle
     * thread.
     */
    ntd->td_wmesg = NULL;
    ntd->td_contended = 0;	/* reset once scheduled */
    ++gd->gd_cnt.v_swtch;
    gd->gd_idle_repeat = 0;

    /*
     * If we were busy waiting record final disposition
     */
    if (gd->gd_indefinite.type)
	    indefinite_done(&gd->gd_indefinite);

havethread_preempted:
    /*
     * If the new target does not need the MP lock and we are holding it,
     * release the MP lock.  If the new target requires the MP lock we have
     * already acquired it for the target.
     */
    ;
haveidle:
    KASSERT(ntd->td_critcount,
	    ("priority problem in lwkt_switch %d %d",
	    td->td_critcount, ntd->td_critcount));

    if (td != ntd) {
	/*
	 * Execute the actual thread switch operation.  This function
	 * returns to the current thread and returns the previous thread
	 * (which may be different from the thread we switched to).
	 *
	 * We are responsible for marking ntd as TDF_RUNNING.
	 */
	KKASSERT((ntd->td_flags & TDF_RUNNING) == 0);
#ifdef DEBUG_LWKT_THREAD
	++switch_count;
#endif
	KTR_LOG(ctxsw_sw, gd->gd_cpuid, ntd);
	ntd->td_flags |= TDF_RUNNING;
	lwkt_switch_return(td->td_switch(ntd));
	/* ntd invalid, td_switch() can return a different thread_t */
    }

    /*
     * catch-all.  XXX is this strictly needed?
     */
    splz_check();

    /* NOTE: current cpu may have changed after switch */
    crit_exit_quick(td);
}

/*
 * Called by assembly in the td_switch (thread restore path) for thread
 * bootstrap cases which do not 'return' to lwkt_switch().
 */
void
lwkt_switch_return(thread_t otd)
{
	globaldata_t rgd;
#ifdef LOOPMASK
	uint64_t tsc_base = rdtsc();
#endif
	int exiting;

	exiting = otd->td_flags & TDF_EXITING;
	cpu_ccfence();

	/*
	 * Check if otd was migrating.  Now that we are on ntd we can finish
	 * up the migration.  This is a bit messy but it is the only place
	 * where td is known to be fully descheduled.
	 *
	 * We can only activate the migration if otd was migrating but not
	 * held on the cpu due to a preemption chain.  We still have to
	 * clear TDF_RUNNING on the old thread either way.
	 *
	 * We are responsible for clearing the previously running thread's
	 * TDF_RUNNING.
	 */
	if ((rgd = otd->td_migrate_gd) != NULL &&
	    (otd->td_flags & TDF_PREEMPT_LOCK) == 0) {
		KKASSERT((otd->td_flags & (TDF_MIGRATING | TDF_RUNNING)) ==
			 (TDF_MIGRATING | TDF_RUNNING));
		otd->td_migrate_gd = NULL;
		otd->td_flags &= ~TDF_RUNNING;
		lwkt_send_ipiq(rgd, lwkt_setcpu_remote, otd);
	} else {
		otd->td_flags &= ~TDF_RUNNING;
	}

	/*
	 * Final exit validations (see lwp_wait()).  Note that otd becomes
	 * invalid the *instant* we set TDF_MP_EXITSIG.
	 *
	 * Use the EXITING status loaded from before we clear TDF_RUNNING,
	 * because if it is not set otd becomes invalid the instant we clear
	 * TDF_RUNNING on it (otherwise, if the system is fast enough, we
	 * might 'steal' TDF_EXITING from another switch-return!).
	 */
	while (exiting) {
		u_int mpflags;

		mpflags = otd->td_mpflags;
		cpu_ccfence();

		if (mpflags & TDF_MP_EXITWAIT) {
			if (atomic_cmpset_int(&otd->td_mpflags, mpflags,
					      mpflags | TDF_MP_EXITSIG)) {
				wakeup(otd);
				break;
			}
		} else {
			if (atomic_cmpset_int(&otd->td_mpflags, mpflags,
					      mpflags | TDF_MP_EXITSIG)) {
				wakeup(otd);
				break;
			}
		}

#ifdef LOOPMASK
		if (tsc_frequency && rdtsc() - tsc_base > tsc_frequency) {
			kprintf("lwkt_switch_return: excessive TDF_EXITING "
				"thread %p\n", otd);
			tsc_base = rdtsc();
		}
#endif
	}
}

/*
 * Request that the target thread preempt the current thread.  Preemption
 * can only occur only:
 *
 *	- If our critical section is the one that we were called with
 *	- The relative priority of the target thread is higher
 *	- The target is not excessively interrupt-nested via td_nest_count
 *	- The target thread holds no tokens.
 *	- The target thread is not already scheduled and belongs to the
 *	  current cpu.
 *	- The current thread is not holding any spin-locks.
 *
 * THE CALLER OF LWKT_PREEMPT() MUST BE IN A CRITICAL SECTION.  Typically
 * this is called via lwkt_schedule() through the td_preemptable callback.
 * critcount is the managed critical priority that we should ignore in order
 * to determine whether preemption is possible (aka usually just the crit
 * priority of lwkt_schedule() itself).
 *
 * Preemption is typically limited to interrupt threads.
 *
 * Operation works in a fairly straight-forward manner.  The normal
 * scheduling code is bypassed and we switch directly to the target
 * thread.  When the target thread attempts to block or switch away
 * code at the base of lwkt_switch() will switch directly back to our
 * thread.  Our thread is able to retain whatever tokens it holds and
 * if the target needs one of them the target will switch back to us
 * and reschedule itself normally.
 */
void
lwkt_preempt(thread_t ntd, int critcount)
{
    struct globaldata *gd = mycpu;
    thread_t xtd;
    thread_t td;
    int save_gd_intr_nesting_level;

    /*
     * The caller has put us in a critical section.  We can only preempt
     * if the caller of the caller was not in a critical section (basically
     * a local interrupt), as determined by the 'critcount' parameter.  We
     * also can't preempt if the caller is holding any spinlocks (even if
     * he isn't in a critical section).  This also handles the tokens test.
     *
     * YYY The target thread must be in a critical section (else it must
     * inherit our critical section?  I dunno yet).
     */
    KASSERT(ntd->td_critcount, ("BADCRIT0 %d", ntd->td_pri));

    td = gd->gd_curthread;
    if (preempt_enable == 0) {
#ifdef DEBUG_LWKT_THREAD
	++preempt_miss;
#endif
	return;
    }
    if (ntd->td_pri <= td->td_pri) {
#ifdef DEBUG_LWKT_THREAD
	++preempt_miss;
#endif
	return;
    }
    if (td->td_critcount > critcount) {
#ifdef DEBUG_LWKT_THREAD
	++preempt_miss;
#endif
	return;
    }
    if (td->td_nest_count >= 2) {
#ifdef DEBUG_LWKT_THREAD
	++preempt_miss;
#endif
	return;
    }
    if (td->td_cscount) {
#ifdef DEBUG_LWKT_THREAD
	++preempt_miss;
#endif
	return;
    }
    if (ntd->td_gd != gd) {
#ifdef DEBUG_LWKT_THREAD
	++preempt_miss;
#endif
	return;
    }

    /*
     * We don't have to check spinlocks here as they will also bump
     * td_critcount.
     *
     * Do not try to preempt if the target thread is holding any tokens.
     * We could try to acquire the tokens but this case is so rare there
     * is no need to support it.
     */
    KKASSERT(gd->gd_spinlocks == 0);

    if (TD_TOKS_HELD(ntd)) {
#ifdef DEBUG_LWKT_THREAD
	++preempt_miss;
#endif
	return;
    }
    if (td == ntd || ((td->td_flags | ntd->td_flags) & TDF_PREEMPT_LOCK)) {
#ifdef DEBUG_LWKT_THREAD
	++preempt_weird;
#endif
	return;
    }
    if (ntd->td_preempted) {
#ifdef DEBUG_LWKT_THREAD
	++preempt_hit;
#endif
	return;
    }
    KKASSERT(gd->gd_processing_ipiq == 0);

    /*
     * Since we are able to preempt the current thread, there is no need to
     * call need_lwkt_resched().
     *
     * We must temporarily clear gd_intr_nesting_level around the switch
     * since switchouts from the target thread are allowed (they will just
     * return to our thread), and since the target thread has its own stack.
     *
     * A preemption must switch back to the original thread, assert the
     * case.
     */
#ifdef DEBUG_LWKT_THREAD
    ++preempt_hit;
#endif
    ntd->td_preempted = td;
    td->td_flags |= TDF_PREEMPT_LOCK;
    KTR_LOG(ctxsw_pre, gd->gd_cpuid, ntd);
    save_gd_intr_nesting_level = gd->gd_intr_nesting_level;
    gd->gd_intr_nesting_level = 0;

    KKASSERT((ntd->td_flags & TDF_RUNNING) == 0);
    ntd->td_flags |= TDF_RUNNING;
    xtd = td->td_switch(ntd);
    KKASSERT(xtd == ntd);
    lwkt_switch_return(xtd);
    gd->gd_intr_nesting_level = save_gd_intr_nesting_level;

    KKASSERT(ntd->td_preempted && (td->td_flags & TDF_PREEMPT_DONE));
    ntd->td_preempted = NULL;
    td->td_flags &= ~(TDF_PREEMPT_LOCK|TDF_PREEMPT_DONE);
}

/*
 * Conditionally call splz() if gd_reqflags indicates work is pending.
 * This will work inside a critical section but not inside a hard code
 * section.
 *
 * (self contained on a per cpu basis)
 */
void
splz_check(void)
{
    globaldata_t gd = mycpu;
    thread_t td = gd->gd_curthread;

    if ((gd->gd_reqflags & RQF_IDLECHECK_MASK) &&
	gd->gd_intr_nesting_level == 0 &&
	td->td_nest_count < 2)
    {
	splz();
    }
}

/*
 * This version is integrated into crit_exit, reqflags has already
 * been tested but td_critcount has not.
 *
 * We only want to execute the splz() on the 1->0 transition of
 * critcount and not in a hard code section or if too deeply nested.
 *
 * NOTE: gd->gd_spinlocks is implied to be 0 when td_critcount is 0.
 */
void
lwkt_maybe_splz(thread_t td)
{
    globaldata_t gd = td->td_gd;

    if (td->td_critcount == 0 &&
	gd->gd_intr_nesting_level == 0 &&
	td->td_nest_count < 2)
    {
	splz();
    }
}

/*
 * Drivers which set up processing co-threads can call this function to
 * run the co-thread at a higher priority and to allow it to preempt
 * normal threads.
 */
void
lwkt_set_interrupt_support_thread(void)
{
	thread_t td = curthread;

        lwkt_setpri_self(TDPRI_INT_SUPPORT);
	td->td_flags |= TDF_INTTHREAD;
	td->td_preemptable = lwkt_preempt;
}


/*
 * This function is used to negotiate a passive release of the current
 * process/lwp designation with the user scheduler, allowing the user
 * scheduler to schedule another user thread.  The related kernel thread
 * (curthread) continues running in the released state.
 */
void
lwkt_passive_release(struct thread *td)
{
    struct lwp *lp = td->td_lwp;

    td->td_release = NULL;
    lwkt_setpri_self(TDPRI_KERN_USER);

    lp->lwp_proc->p_usched->release_curproc(lp);
}


/*
 * This implements a LWKT yield, allowing a kernel thread to yield to other
 * kernel threads at the same or higher priority.  This function can be
 * called in a tight loop and will typically only yield once per tick.
 *
 * Most kernel threads run at the same priority in order to allow equal
 * sharing.
 *
 * (self contained on a per cpu basis)
 */
void
lwkt_yield(void)
{
    globaldata_t gd = mycpu;
    thread_t td = gd->gd_curthread;

    /*
     * Should never be called with spinlocks held but there is a path
     * via ACPI where it might happen.
     */
    if (gd->gd_spinlocks)
	return;

    /*
     * Safe to call splz if we are not too-heavily nested.
     */
    if ((gd->gd_reqflags & RQF_IDLECHECK_MASK) && td->td_nest_count < 2)
	splz();

    /*
     * Caller allows switching
     */
    if (lwkt_resched_wanted()) {
	atomic_set_int(&td->td_mpflags, TDF_MP_DIDYIELD);
	lwkt_schedule_self(td);
	lwkt_switch();
    }
}

/*
 * The quick version processes pending interrupts and higher-priority
 * LWKT threads but will not round-robin same-priority LWKT threads.
 *
 * When called while attempting to return to userland the only same-pri
 * threads are the ones which have already tried to become the current
 * user process.
 */
void
lwkt_yield_quick(void)
{
    globaldata_t gd = mycpu;
    thread_t td = gd->gd_curthread;

    if ((gd->gd_reqflags & RQF_IDLECHECK_MASK) && td->td_nest_count < 2)
	splz();
    if (lwkt_resched_wanted()) {
	crit_enter();
	if (TAILQ_FIRST(&gd->gd_tdrunq) == td) {
	    clear_lwkt_resched();
	} else {
	    atomic_set_int(&td->td_mpflags, TDF_MP_DIDYIELD);
	    lwkt_schedule_self(curthread);
	    lwkt_switch();
	}
	crit_exit();
    }
}

/*
 * This yield is designed for kernel threads with a user context.
 *
 * The kernel acting on behalf of the user is potentially cpu-bound,
 * this function will efficiently allow other threads to run and also
 * switch to other processes by releasing.
 *
 * The lwkt_user_yield() function is designed to have very low overhead
 * if no yield is determined to be needed.
 */
void
lwkt_user_yield(void)
{
    globaldata_t gd = mycpu;
    thread_t td = gd->gd_curthread;

    /*
     * Should never be called with spinlocks held but there is a path
     * via ACPI where it might happen.
     */
    if (gd->gd_spinlocks)
	return;

    /*
     * Always run any pending interrupts in case we are in a critical
     * section.
     */
    if ((gd->gd_reqflags & RQF_IDLECHECK_MASK) && td->td_nest_count < 2)
	splz();

    /*
     * Switch (which forces a release) if another kernel thread needs
     * the cpu, if userland wants us to resched, or if our kernel
     * quantum has run out.
     */
    if (lwkt_resched_wanted() ||
	user_resched_wanted())
    {
	lwkt_switch();
    }

#if 0
    /*
     * Reacquire the current process if we are released.
     *
     * XXX not implemented atm.  The kernel may be holding locks and such,
     *     so we want the thread to continue to receive cpu.
     */
    if (td->td_release == NULL && lp) {
	lp->lwp_proc->p_usched->acquire_curproc(lp);
	td->td_release = lwkt_passive_release;
	lwkt_setpri_self(TDPRI_USER_NORM);
    }
#endif
}

/*
 * Generic schedule.  Possibly schedule threads belonging to other cpus and
 * deal with threads that might be blocked on a wait queue.
 *
 * We have a little helper inline function which does additional work after
 * the thread has been enqueued, including dealing with preemption and
 * setting need_lwkt_resched() (which prevents the kernel from returning
 * to userland until it has processed higher priority threads).
 *
 * It is possible for this routine to be called after a failed _enqueue
 * (due to the target thread migrating, sleeping, or otherwise blocked).
 * We have to check that the thread is actually on the run queue!
 */
static __inline
void
_lwkt_schedule_post(globaldata_t gd, thread_t ntd, int ccount)
{
    if (ntd->td_flags & TDF_RUNQ) {
	if (ntd->td_preemptable) {
	    ntd->td_preemptable(ntd, ccount);	/* YYY +token */
	}
    }
}

static __inline
void
_lwkt_schedule(thread_t td)
{
    globaldata_t mygd = mycpu;

    KASSERT(td != &td->td_gd->gd_idlethread,
	    ("lwkt_schedule(): scheduling gd_idlethread is illegal!"));
    KKASSERT((td->td_flags & TDF_MIGRATING) == 0);
    crit_enter_gd(mygd);
    KKASSERT(td->td_lwp == NULL ||
	     (td->td_lwp->lwp_mpflags & LWP_MP_ONRUNQ) == 0);

    if (td == mygd->gd_curthread) {
	_lwkt_enqueue(td);
    } else {
	/*
	 * If we own the thread, there is no race (since we are in a
	 * critical section).  If we do not own the thread there might
	 * be a race but the target cpu will deal with it.
	 */
	if (td->td_gd == mygd) {
	    _lwkt_enqueue(td);
	    _lwkt_schedule_post(mygd, td, 1);
	} else {
	    lwkt_send_ipiq3(td->td_gd, lwkt_schedule_remote, td, 0);
	}
    }
    crit_exit_gd(mygd);
}

void
lwkt_schedule(thread_t td)
{
    _lwkt_schedule(td);
}

void
lwkt_schedule_noresched(thread_t td)	/* XXX not impl */
{
    _lwkt_schedule(td);
}

/*
 * When scheduled remotely if frame != NULL the IPIQ is being
 * run via doreti or an interrupt then preemption can be allowed.
 *
 * To allow preemption we have to drop the critical section so only
 * one is present in _lwkt_schedule_post.
 */
static void
lwkt_schedule_remote(void *arg, int arg2, struct intrframe *frame)
{
    thread_t td = curthread;
    thread_t ntd = arg;

    if (frame && ntd->td_preemptable) {
	crit_exit_noyield(td);
	_lwkt_schedule(ntd);
	crit_enter_quick(td);
    } else {
	_lwkt_schedule(ntd);
    }
}

/*
 * Thread migration using a 'Pull' method.  The thread may or may not be
 * the current thread.  It MUST be descheduled and in a stable state.
 * lwkt_giveaway() must be called on the cpu owning the thread.
 *
 * At any point after lwkt_giveaway() is called, the target cpu may
 * 'pull' the thread by calling lwkt_acquire().
 *
 * We have to make sure the thread is not sitting on a per-cpu tsleep
 * queue or it will blow up when it moves to another cpu.
 *
 * MPSAFE - must be called under very specific conditions.
 */
void
lwkt_giveaway(thread_t td)
{
    globaldata_t gd = mycpu;

    crit_enter_gd(gd);
    if (td->td_flags & TDF_TSLEEPQ)
	tsleep_remove(td);
    KKASSERT(td->td_gd == gd);
    TAILQ_REMOVE(&gd->gd_tdallq, td, td_allq);
    td->td_flags |= TDF_MIGRATING;
    crit_exit_gd(gd);
}

void
lwkt_acquire(thread_t td)
{
    globaldata_t gd;
    globaldata_t mygd;

    KKASSERT(td->td_flags & TDF_MIGRATING);
    gd = td->td_gd;
    mygd = mycpu;
    if (gd != mycpu) {
#ifdef LOOPMASK
	uint64_t tsc_base = rdtsc();
#endif
	cpu_lfence();
	KKASSERT((td->td_flags & TDF_RUNQ) == 0);
	crit_enter_gd(mygd);
	DEBUG_PUSH_INFO("lwkt_acquire");
	while (td->td_flags & (TDF_RUNNING|TDF_PREEMPT_LOCK)) {
	    lwkt_process_ipiq();
	    cpu_lfence();
#ifdef _KERNEL_VIRTUAL
	    vkernel_yield();
#endif
#ifdef LOOPMASK
	    if (tsc_frequency && rdtsc() - tsc_base > tsc_frequency) {
		    kprintf("lwkt_acquire: stuck td %p td->td_flags %08x\n",
			    td, td->td_flags);
		    tsc_base = rdtsc();
	    }
#endif
	}
	DEBUG_POP_INFO();
	cpu_mfence();
	td->td_gd = mygd;
	TAILQ_INSERT_TAIL(&mygd->gd_tdallq, td, td_allq);
	td->td_flags &= ~TDF_MIGRATING;
	crit_exit_gd(mygd);
    } else {
	crit_enter_gd(mygd);
	TAILQ_INSERT_TAIL(&mygd->gd_tdallq, td, td_allq);
	td->td_flags &= ~TDF_MIGRATING;
	crit_exit_gd(mygd);
    }
}

/*
 * Generic deschedule.  Descheduling threads other then your own should be
 * done only in carefully controlled circumstances.  Descheduling is
 * asynchronous.
 *
 * This function may block if the cpu has run out of messages.
 */
void
lwkt_deschedule(thread_t td)
{
    crit_enter();
    if (td == curthread) {
	_lwkt_dequeue(td);
    } else {
	if (td->td_gd == mycpu) {
	    _lwkt_dequeue(td);
	} else {
	    lwkt_send_ipiq(td->td_gd, (ipifunc1_t)lwkt_deschedule, td);
	}
    }
    crit_exit();
}

/*
 * Set the target thread's priority.  This routine does not automatically
 * switch to a higher priority thread, LWKT threads are not designed for
 * continuous priority changes.  Yield if you want to switch.
 */
void
lwkt_setpri(thread_t td, int pri)
{
    if (td->td_pri != pri) {
	KKASSERT(pri >= 0);
	crit_enter();
	if (td->td_flags & TDF_RUNQ) {
	    KKASSERT(td->td_gd == mycpu);
	    _lwkt_dequeue(td);
	    td->td_pri = pri;
	    _lwkt_enqueue(td);
	} else {
	    td->td_pri = pri;
	}
	crit_exit();
    }
}

/*
 * Set the initial priority for a thread prior to it being scheduled for
 * the first time.  The thread MUST NOT be scheduled before or during
 * this call.  The thread may be assigned to a cpu other then the current
 * cpu.
 *
 * Typically used after a thread has been created with TDF_STOPPREQ,
 * and before the thread is initially scheduled.
 */
void
lwkt_setpri_initial(thread_t td, int pri)
{
    KKASSERT(pri >= 0);
    KKASSERT((td->td_flags & TDF_RUNQ) == 0);
    td->td_pri = pri;
}

void
lwkt_setpri_self(int pri)
{
    thread_t td = curthread;

    KKASSERT(pri >= 0 && pri <= TDPRI_MAX);
    crit_enter();
    if (td->td_flags & TDF_RUNQ) {
	_lwkt_dequeue(td);
	td->td_pri = pri;
	_lwkt_enqueue(td);
    } else {
	td->td_pri = pri;
    }
    crit_exit();
}

/*
 * hz tick scheduler clock for LWKT threads
 */
void
lwkt_schedulerclock(thread_t td)
{
    globaldata_t gd = td->td_gd;
    thread_t xtd;

    xtd = TAILQ_FIRST(&gd->gd_tdrunq);
    if (xtd == td) {
	/*
	 * If the current thread is at the head of the runq shift it to the
	 * end of any equal-priority threads and request a LWKT reschedule
	 * if it moved.
	 *
	 * Ignore upri in this situation.  There will only be one user thread
	 * in user mode, all others will be user threads running in kernel
	 * mode and we have to make sure they get some cpu.
	 */
	xtd = TAILQ_NEXT(td, td_threadq);
	if (xtd && xtd->td_pri == td->td_pri) {
	    TAILQ_REMOVE(&gd->gd_tdrunq, td, td_threadq);
	    while (xtd && xtd->td_pri == td->td_pri)
		xtd = TAILQ_NEXT(xtd, td_threadq);
	    if (xtd)
		TAILQ_INSERT_BEFORE(xtd, td, td_threadq);
	    else
		TAILQ_INSERT_TAIL(&gd->gd_tdrunq, td, td_threadq);
	    need_lwkt_resched();
	}
    } else if (xtd) {
	/*
	 * If we scheduled a thread other than the one at the head of the
	 * queue always request a reschedule every tick.
	 */
	need_lwkt_resched();
    }
    /* else curthread probably the idle thread, no need to reschedule */
}

/*
 * Migrate the current thread to the specified cpu.
 *
 * This is accomplished by descheduling ourselves from the current cpu
 * and setting td_migrate_gd.  The lwkt_switch() code will detect that the
 * 'old' thread wants to migrate after it has been completely switched out
 * and will complete the migration.
 *
 * TDF_MIGRATING prevents scheduling races while the thread is being migrated.
 *
 * We must be sure to release our current process designation (if a user
 * process) before clearing out any tsleepq we are on because the release
 * code may re-add us.
 *
 * We must be sure to remove ourselves from the current cpu's tsleepq
 * before potentially moving to another queue.  The thread can be on
 * a tsleepq due to a left-over tsleep_interlock().
 */

void
lwkt_setcpu_self(globaldata_t rgd)
{
    thread_t td = curthread;

    if (td->td_gd != rgd) {
	crit_enter_quick(td);

	if (td->td_release)
	    td->td_release(td);
	if (td->td_flags & TDF_TSLEEPQ)
	    tsleep_remove(td);

	/*
	 * Set TDF_MIGRATING to prevent a spurious reschedule while we are
	 * trying to deschedule ourselves and switch away, then deschedule
	 * ourself, remove us from tdallq, and set td_migrate_gd.  Finally,
	 * call lwkt_switch() to complete the operation.
	 */
	td->td_flags |= TDF_MIGRATING;
	lwkt_deschedule_self(td);
	TAILQ_REMOVE(&td->td_gd->gd_tdallq, td, td_allq);
	td->td_migrate_gd = rgd;
	lwkt_switch();

	/*
	 * We are now on the target cpu
	 */
	KKASSERT(rgd == mycpu);
	TAILQ_INSERT_TAIL(&rgd->gd_tdallq, td, td_allq);
	crit_exit_quick(td);
    }
}

void
lwkt_migratecpu(int cpuid)
{
	globaldata_t rgd;

	rgd = globaldata_find(cpuid);
	lwkt_setcpu_self(rgd);
}

/*
 * Remote IPI for cpu migration (called while in a critical section so we
 * do not have to enter another one).
 *
 * The thread (td) has already been completely descheduled from the
 * originating cpu and we can simply assert the case.  The thread is
 * assigned to the new cpu and enqueued.
 *
 * The thread will re-add itself to tdallq when it resumes execution.
 */
static void
lwkt_setcpu_remote(void *arg)
{
    thread_t td = arg;
    globaldata_t gd = mycpu;

    KKASSERT((td->td_flags & (TDF_RUNNING|TDF_PREEMPT_LOCK)) == 0);
    td->td_gd = gd;
    cpu_mfence();
    td->td_flags &= ~TDF_MIGRATING;
    KKASSERT(td->td_migrate_gd == NULL);
    KKASSERT(td->td_lwp == NULL ||
	    (td->td_lwp->lwp_mpflags & LWP_MP_ONRUNQ) == 0);
    _lwkt_enqueue(td);
}

struct lwp *
lwkt_preempted_proc(void)
{
    thread_t td = curthread;
    while (td->td_preempted)
	td = td->td_preempted;
    return(td->td_lwp);
}

/*
 * Create a kernel process/thread/whatever.  It shares it's address space
 * with proc0 - ie: kernel only.
 *
 * If the cpu is not specified one will be selected.  In the future
 * specifying a cpu of -1 will enable kernel thread migration between
 * cpus.
 */
int
lwkt_create(void (*func)(void *), void *arg, struct thread **tdp,
	    thread_t template, int tdflags, int cpu, const char *fmt, ...)
{
    thread_t td;
    __va_list ap;

    td = lwkt_alloc_thread(template, LWKT_THREAD_STACK, cpu,
			   tdflags);
    if (tdp)
	*tdp = td;
    cpu_set_thread_handler(td, lwkt_exit, func, arg);

    /*
     * Set up arg0 for 'ps' etc
     */
    __va_start(ap, fmt);
    kvsnprintf(td->td_comm, sizeof(td->td_comm), fmt, ap);
    __va_end(ap);

    /*
     * Schedule the thread to run
     */
    if (td->td_flags & TDF_NOSTART)
	td->td_flags &= ~TDF_NOSTART;
    else
	lwkt_schedule(td);
    return 0;
}

/*
 * Destroy an LWKT thread.   Warning!  This function is not called when
 * a process exits, cpu_proc_exit() directly calls cpu_thread_exit() and
 * uses a different reaping mechanism.
 */
void
lwkt_exit(void)
{
    thread_t td = curthread;
    thread_t std;
    globaldata_t gd;

    /*
     * Do any cleanup that might block here
     */
    biosched_done(td);
    dsched_exit_thread(td);

    /*
     * Get us into a critical section to interlock gd_freetd and loop
     * until we can get it freed.
     *
     * We have to cache the current td in gd_freetd because objcache_put()ing
     * it would rip it out from under us while our thread is still active.
     *
     * We are the current thread so of course our own TDF_RUNNING bit will
     * be set, so unlike the lwp reap code we don't wait for it to clear.
     */
    gd = mycpu;
    crit_enter_quick(td);
    for (;;) {
	if (td->td_refs) {
	    tsleep(td, 0, "tdreap", 1);
	    continue;
	}
	if ((std = gd->gd_freetd) != NULL) {
	    KKASSERT((std->td_flags & (TDF_RUNNING|TDF_PREEMPT_LOCK)) == 0);
	    gd->gd_freetd = NULL;
	    objcache_put(thread_cache, std);
	    continue;
	}
	break;
    }

    /*
     * Remove thread resources from kernel lists and deschedule us for
     * the last time.  We cannot block after this point or we may end
     * up with a stale td on the tsleepq.
     *
     * None of this may block, the critical section is the only thing
     * protecting tdallq and the only thing preventing new lwkt_hold()
     * thread refs now.
     */
    if (td->td_flags & TDF_TSLEEPQ)
	tsleep_remove(td);
    lwkt_deschedule_self(td);
    lwkt_remove_tdallq(td);
    KKASSERT(td->td_refs == 0);

    /*
     * Final cleanup
     */
    KKASSERT(gd->gd_freetd == NULL);
    if (td->td_flags & TDF_ALLOCATED_THREAD)
	gd->gd_freetd = td;
    cpu_thread_exit();
}

void
lwkt_remove_tdallq(thread_t td)
{
    KKASSERT(td->td_gd == mycpu);
    TAILQ_REMOVE(&td->td_gd->gd_tdallq, td, td_allq);
}

/*
 * Code reduction and branch prediction improvements.  Call/return
 * overhead on modern cpus often degenerates into 0 cycles due to
 * the cpu's branch prediction hardware and return pc cache.  We
 * can take advantage of this by not inlining medium-complexity
 * functions and we can also reduce the branch prediction impact
 * by collapsing perfectly predictable branches into a single
 * procedure instead of duplicating it.
 *
 * Is any of this noticeable?  Probably not, so I'll take the
 * smaller code size.
 */
void
crit_exit_wrapper(__DEBUG_CRIT_ARG__)
{
    _crit_exit(mycpu __DEBUG_CRIT_PASS_ARG__);
}

void
crit_panic(void)
{
    thread_t td = curthread;
    int lcrit = td->td_critcount;

    td->td_critcount = 0;
    cpu_ccfence();
    panic("td_critcount is/would-go negative! %p %d", td, lcrit);
    /* NOT REACHED */
}

/*
 * Called from debugger/panic on cpus which have been stopped.  We must still
 * process the IPIQ while stopped.
 *
 * If we are dumping also try to process any pending interrupts.  This may
 * or may not work depending on the state of the cpu at the point it was
 * stopped.
 */
void
lwkt_smp_stopped(void)
{
    globaldata_t gd = mycpu;

    if (dumping) {
	lwkt_process_ipiq();
	--gd->gd_intr_nesting_level;
	splz();
	++gd->gd_intr_nesting_level;
    } else {
	lwkt_process_ipiq();
    }
    cpu_smp_stopped();
}
