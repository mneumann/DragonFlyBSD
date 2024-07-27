/*-
 * Copyright (c) 1992 Terrence R. Lambert.
 * Copyright (C) 1994, David Greenman
 * Copyright (c) 1982, 1987, 1990, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * William Jolitz.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
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
 *	from: @(#)machdep.c	7.4 (Berkeley) 6/3/91
 * $FreeBSD: src/sys/i386/i386/machdep.c,v 1.385.2.30 2003/05/31 08:48:05 alc Exp $
 */

#include "opt_ddb.h"
#include "opt_inet.h"
#include "opt_msgbuf.h"
#include "opt_swap.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/sysmsg.h>
#include <sys/signalvar.h>
#include <sys/kernel.h>
#include <sys/linker.h>
#include <sys/malloc.h>
#include <sys/proc.h>
#include <sys/buf.h>
#include <sys/reboot.h>
#include <sys/mbuf.h>
#include <sys/msgbuf.h>
#include <sys/sysent.h>
#include <sys/sysctl.h>
#include <sys/vmmeter.h>
#include <sys/bus.h>
#include <sys/usched.h>
#include <sys/reg.h>

#include <vm/vm.h>
#include <vm/vm_param.h>
#include <sys/lock.h>
#include <vm/vm_kern.h>
#include <vm/vm_object.h>
#include <vm/vm_page.h>
#include <vm/vm_map.h>
#include <vm/vm_pager.h>
#include <vm/vm_extern.h>

#include <sys/thread2.h>

#include <sys/exec.h>
#include <sys/cons.h>

#include <ddb/ddb.h>

#include <machine/cpu.h>
#include <machine/clock.h>
#include <machine/specialreg.h>
#include <machine/md_var.h>
#include <machine/pcb.h>
#include <machine/pcb_ext.h>
#include <machine/globaldata.h>		/* CPU_prvspace */
#include <machine/smp.h>
#include <machine/cputypes.h>

#include <bus/isa/rtc.h>
#include <sys/random.h>
#include <sys/ptrace.h>
#include <machine/sigframe.h>
#include <unistd.h>		/* umtx_* functions */

extern void dblfault_handler (void);

static void set_fpregs_xmm (struct save87 *, struct savexmm *);
static void fill_fpregs_xmm (struct savexmm *, struct save87 *);

int64_t tsc_offsets[MAXCPU];

#if defined(SWTCH_OPTIM_STATS)
extern int swtch_optim_stats;
SYSCTL_INT(_debug, OID_AUTO, swtch_optim_stats,
	CTLFLAG_RD, &swtch_optim_stats, 0, "");
SYSCTL_INT(_debug, OID_AUTO, tlb_flush_count,
	CTLFLAG_RD, &tlb_flush_count, 0, "");
#endif

static int
sysctl_hw_physmem(SYSCTL_HANDLER_ARGS)
{
	u_long pmem = ctob(physmem);
	int error;

	error = sysctl_handle_long(oidp, &pmem, 0, req);

	return (error);
}

SYSCTL_PROC(_hw, HW_PHYSMEM, physmem, CTLTYPE_ULONG|CTLFLAG_RD,
	0, 0, sysctl_hw_physmem, "LU", "Total system memory in bytes (number of pages * page size)");

static int
sysctl_hw_usermem(SYSCTL_HANDLER_ARGS)
{
	u_long usermem = ctob(Maxmem - vmstats.v_wire_count);
	int error;

	error = sysctl_handle_long(oidp, &usermem, 0, req);

	return (error);
}

SYSCTL_PROC(_hw, HW_USERMEM, usermem, CTLTYPE_ULONG|CTLFLAG_RD,
	0, 0, sysctl_hw_usermem, "LU", "");

SYSCTL_ULONG(_hw, OID_AUTO, availpages, CTLFLAG_RD, &Maxmem, 0, "");

/*
 * Send an interrupt to process.
 *
 * Stack is set up to allow sigcode stored
 * at top to call routine, followed by kcall
 * to sigreturn routine below.  After sigreturn
 * resets the signal mask, the stack, and the
 * frame pointer, it returns to the user
 * specified pc, psl.
 */
void
sendsig(sig_t catcher, int sig, sigset_t *mask, u_long code)
{
	struct lwp *lp = curthread->td_lwp;
	struct proc *p = lp->lwp_proc;
	struct trapframe *regs;
	struct sigacts *psp = p->p_sigacts;
	struct sigframe sf, *sfp;
	int oonstack;
	char *sp;

	regs = lp->lwp_md.md_regs;
	oonstack = (lp->lwp_sigstk.ss_flags & SS_ONSTACK) ? 1 : 0;

	/* Save user context */
	bzero(&sf, sizeof(struct sigframe));
	sf.sf_uc.uc_sigmask = *mask;
	sf.sf_uc.uc_stack = lp->lwp_sigstk;
	sf.sf_uc.uc_mcontext.mc_onstack = oonstack;
	KKASSERT(__offsetof(struct trapframe, tf_rdi) == 0);
	/* gcc8 craps out on -Warray-bounds w/ optimized bcopy */
	_bcopy(regs, &sf.sf_uc.uc_mcontext.mc_rdi, sizeof(struct trapframe));

	/* Make the size of the saved context visible to userland */
	sf.sf_uc.uc_mcontext.mc_len = sizeof(sf.sf_uc.uc_mcontext);

	/* Allocate and validate space for the signal handler context. */
        if ((lp->lwp_flags & LWP_ALTSTACK) != 0 && !oonstack &&
	    SIGISMEMBER(psp->ps_sigonstack, sig)) {
		sp = (char *)lp->lwp_sigstk.ss_sp + lp->lwp_sigstk.ss_size -
		    sizeof(struct sigframe);
		lp->lwp_sigstk.ss_flags |= SS_ONSTACK;
	} else {
		/* We take red zone into account */
		sp = (char *)regs->tf_rsp - sizeof(struct sigframe) - 128;
	}

	/* Align to 16 bytes */
	sfp = (struct sigframe *)((intptr_t)sp & ~0xFUL);

	/* Translate the signal is appropriate */
	if (p->p_sysent->sv_sigtbl) {
		if (sig <= p->p_sysent->sv_sigsize)
			sig = p->p_sysent->sv_sigtbl[_SIG_IDX(sig)];
	}

	/*
	 * Build the argument list for the signal handler.
	 *
	 * Arguments are in registers (%rdi, %rsi, %rdx, %rcx)
	 */
	regs->tf_rdi = sig;				/* argument 1 */
	regs->tf_rdx = (register_t)&sfp->sf_uc;		/* argument 3 */

	if (SIGISMEMBER(psp->ps_siginfo, sig)) {
		/*
		 * Signal handler installed with SA_SIGINFO.
		 *
		 * action(signo, siginfo, ucontext)
		 */
		regs->tf_rsi = (register_t)&sfp->sf_si;	/* argument 2 */
		regs->tf_rcx = (register_t)regs->tf_err; /* argument 4 */
		sf.sf_ahu.sf_action = (__siginfohandler_t *)catcher;

		/* fill siginfo structure */
		sf.sf_si.si_signo = sig;
		sf.sf_si.si_pid = psp->ps_frominfo[sig].pid;
		sf.sf_si.si_uid = psp->ps_frominfo[sig].uid;
		sf.sf_si.si_code = code;
		sf.sf_si.si_addr = (void *)regs->tf_addr;
	} else {
		/*
		 * Old FreeBSD-style arguments.
		 *
		 * handler (signo, code, [uc], addr)
		 */
		regs->tf_rsi = (register_t)code;	/* argument 2 */
		regs->tf_rcx = (register_t)regs->tf_addr; /* argument 4 */
		sf.sf_ahu.sf_handler = catcher;
	}

#if 0
	/*
	 * If we're a vm86 process, we want to save the segment registers.
	 * We also change eflags to be our emulated eflags, not the actual
	 * eflags.
	 */
	if (regs->tf_eflags & PSL_VM) {
		struct trapframe_vm86 *tf = (struct trapframe_vm86 *)regs;
		struct vm86_kernel *vm86 = &lp->lwp_thread->td_pcb->pcb_ext->ext_vm86;

		sf.sf_uc.uc_mcontext.mc_gs = tf->tf_vm86_gs;
		sf.sf_uc.uc_mcontext.mc_fs = tf->tf_vm86_fs;
		sf.sf_uc.uc_mcontext.mc_es = tf->tf_vm86_es;
		sf.sf_uc.uc_mcontext.mc_ds = tf->tf_vm86_ds;

		if (vm86->vm86_has_vme == 0)
			sf.sf_uc.uc_mcontext.mc_eflags =
			    (tf->tf_eflags & ~(PSL_VIF | PSL_VIP)) |
			    (vm86->vm86_eflags & (PSL_VIF | PSL_VIP));

		/*
		 * Clear PSL_NT to inhibit T_TSSFLT faults on return from
		 * syscalls made by the signal handler.  This just avoids
		 * wasting time for our lazy fixup of such faults.  PSL_NT
		 * does nothing in vm86 mode, but vm86 programs can set it
		 * almost legitimately in probes for old cpu types.
		 */
		tf->tf_eflags &= ~(PSL_VM | PSL_NT | PSL_VIF | PSL_VIP);
	}
#endif

	/*
	 * Save the FPU state and reinit the FP unit
	 */
	npxpush(&sf.sf_uc.uc_mcontext);

	/*
	 * Copy the sigframe out to the user's stack.
	 */
	if (copyout(&sf, sfp, sizeof(struct sigframe)) != 0) {
		/*
		 * Something is wrong with the stack pointer.
		 * ...Kill the process.
		 */
		sigexit(lp, SIGILL);
	}

	regs->tf_rsp = (register_t)sfp;
	regs->tf_rip = trunc_page64(PS_STRINGS - *(p->p_sysent->sv_szsigcode));
	regs->tf_rip -= SZSIGCODE_EXTRA_BYTES;

	/*
	 * x86 abi specifies that the direction flag must be cleared
	 * on function entry
	 */
	regs->tf_rflags &= ~(PSL_T|PSL_D);

	/*
	 * 64 bit mode has a code and stack selector but
	 * no data or extra selector.  %fs and %gs are not
	 * stored in-context.
	 */
	regs->tf_cs = _ucodesel;
	regs->tf_ss = _udatasel;
}

/*
 * Sanitize the trapframe for a virtual kernel passing control to a custom
 * VM context.  Remove any items that would otherwise create a privilege
 * issue.
 *
 * XXX at the moment we allow userland to set the resume flag.  Is this a
 * bad idea?
 */
int
cpu_sanitize_frame(struct trapframe *frame)
{
	frame->tf_cs = _ucodesel;
	frame->tf_ss = _udatasel;
	/* XXX VM (8086) mode not supported? */
	frame->tf_rflags &= (PSL_RF | PSL_USERCHANGE | PSL_VM_UNSUPP);
	frame->tf_rflags |= PSL_RESERVED_DEFAULT | PSL_I;

	return(0);
}

/*
 * Sanitize the tls so loading the descriptor does not blow up
 * on us.  For x86_64 we don't have to do anything.
 */
int
cpu_sanitize_tls(struct savetls *tls)
{
	return(0);
}

/*
 * sigreturn(ucontext_t *sigcntxp)
 *
 * System call to cleanup state after a signal
 * has been taken.  Reset signal mask and
 * stack state from context left by sendsig (above).
 * Return to previous pc and psl as specified by
 * context left by sendsig. Check carefully to
 * make sure that the user has not modified the
 * state to gain improper privileges.
 */
#define	EFL_SECURE(ef, oef)	((((ef) ^ (oef)) & ~PSL_USERCHANGE) == 0)
#define	CS_SECURE(cs)		(ISPL(cs) == SEL_UPL)

int
sys_sigreturn(struct sysmsg *sysmsg, const struct sigreturn_args *uap)
{
	struct lwp *lp = curthread->td_lwp;
	struct trapframe *regs;
	ucontext_t uc;
	ucontext_t *ucp;
	register_t rflags;
	int cs;
	int error;

	/*
	 * We have to copy the information into kernel space so userland
	 * can't modify it while we are sniffing it.
	 */
	regs = lp->lwp_md.md_regs;
	error = copyin(uap->sigcntxp, &uc, sizeof(uc));
	if (error)
		return (error);
	ucp = &uc;
	rflags = ucp->uc_mcontext.mc_rflags;

	/* VM (8086) mode not supported */
	rflags &= ~PSL_VM_UNSUPP;

#if 0
	if (eflags & PSL_VM) {
		struct trapframe_vm86 *tf = (struct trapframe_vm86 *)regs;
		struct vm86_kernel *vm86;

		/*
		 * if pcb_ext == 0 or vm86_inited == 0, the user hasn't
		 * set up the vm86 area, and we can't enter vm86 mode.
		 */
		if (lp->lwp_thread->td_pcb->pcb_ext == 0)
			return (EINVAL);
		vm86 = &lp->lwp_thread->td_pcb->pcb_ext->ext_vm86;
		if (vm86->vm86_inited == 0)
			return (EINVAL);

		/* go back to user mode if both flags are set */
		if ((eflags & PSL_VIP) && (eflags & PSL_VIF))
			trapsignal(lp->lwp_proc, SIGBUS, 0);

		if (vm86->vm86_has_vme) {
			eflags = (tf->tf_eflags & ~VME_USERCHANGE) |
			    (eflags & VME_USERCHANGE) | PSL_VM;
		} else {
			vm86->vm86_eflags = eflags;	/* save VIF, VIP */
			eflags = (tf->tf_eflags & ~VM_USERCHANGE) |					    (eflags & VM_USERCHANGE) | PSL_VM;
		}
		bcopy(&ucp.uc_mcontext.mc_gs, tf, sizeof(struct trapframe));
		tf->tf_eflags = eflags;
		tf->tf_vm86_ds = tf->tf_ds;
		tf->tf_vm86_es = tf->tf_es;
		tf->tf_vm86_fs = tf->tf_fs;
		tf->tf_vm86_gs = tf->tf_gs;
		tf->tf_ds = _udatasel;
		tf->tf_es = _udatasel;
#if 0
		tf->tf_fs = _udatasel;
		tf->tf_gs = _udatasel;
#endif
	} else
#endif
	{
		/*
		 * Don't allow users to change privileged or reserved flags.
		 */
		/*
		 * XXX do allow users to change the privileged flag PSL_RF.
		 * The cpu sets PSL_RF in tf_eflags for faults.  Debuggers
		 * should sometimes set it there too.  tf_eflags is kept in
		 * the signal context during signal handling and there is no
		 * other place to remember it, so the PSL_RF bit may be
		 * corrupted by the signal handler without us knowing.
		 * Corruption of the PSL_RF bit at worst causes one more or
		 * one less debugger trap, so allowing it is fairly harmless.
		 */
		if (!EFL_SECURE(rflags & ~PSL_RF, regs->tf_rflags & ~PSL_RF)) {
			kprintf("sigreturn: rflags = 0x%lx\n", (long)rflags);
			return(EINVAL);
		}

		/*
		 * Don't allow users to load a valid privileged %cs.  Let the
		 * hardware check for invalid selectors, excess privilege in
		 * other selectors, invalid %eip's and invalid %esp's.
		 */
		cs = ucp->uc_mcontext.mc_cs;
		if (!CS_SECURE(cs)) {
			kprintf("sigreturn: cs = 0x%x\n", cs);
			trapsignal(lp, SIGBUS, T_PROTFLT);
			return(EINVAL);
		}
		bcopy(&ucp->uc_mcontext.mc_rdi, regs, sizeof(struct trapframe));
	}

	/*
	 * Restore the FPU state from the frame
	 */
	npxpop(&ucp->uc_mcontext);

	if (ucp->uc_mcontext.mc_onstack & 1)
		lp->lwp_sigstk.ss_flags |= SS_ONSTACK;
	else
		lp->lwp_sigstk.ss_flags &= ~SS_ONSTACK;

	lp->lwp_sigmask = ucp->uc_sigmask;
	SIG_CANTMASK(lp->lwp_sigmask);
	return(EJUSTRETURN);
}

/*
 * cpu_idle() represents the idle LWKT.  You cannot return from this function
 * (unless you want to blow things up!).  Instead we look for runnable threads
 * and loop or halt as appropriate.  Giant is not held on entry to the thread.
 *
 * The main loop is entered with a critical section held, we must release
 * the critical section before doing anything else.  lwkt_switch() will
 * check for pending interrupts due to entering and exiting its own
 * critical section.
 *
 * Note on cpu_idle_hlt:  On an SMP system we rely on a scheduler IPI
 * to wake a HLTed cpu up.
 */
__read_mostly static int	cpu_idle_hlt = 1;
SYSCTL_INT(_machdep, OID_AUTO, cpu_idle_hlt, CTLFLAG_RW,
    &cpu_idle_hlt, 0, "Idle loop HLT enable");

void
cpu_idle(void)
{
	struct thread *td = curthread;
	struct mdglobaldata *gd = mdcpu;
	int reqflags;

	crit_exit();
	KKASSERT(td->td_critcount == 0);
	cpu_enable_intr();

	for (;;) {
		/*
		 * See if there are any LWKTs ready to go.
		 */
		lwkt_switch();

		/*
		 * The idle loop halts only if no threads are scheduleable
		 * and no signals have occurred.
		 */
		if (cpu_idle_hlt &&
		    (td->td_gd->gd_reqflags & RQF_IDLECHECK_WK_MASK) == 0) {
			splz();
			if ((td->td_gd->gd_reqflags & RQF_IDLECHECK_WK_MASK) == 0) {
#ifdef DEBUGIDLE
				struct timeval tv1, tv2;
				gettimeofday(&tv1, NULL);
#endif
				reqflags = gd->mi.gd_reqflags &
					   ~RQF_IDLECHECK_WK_MASK;
				KKASSERT(gd->mi.gd_processing_ipiq == 0);
				umtx_sleep(&gd->mi.gd_reqflags, reqflags,
					   1000000);
#ifdef DEBUGIDLE
				gettimeofday(&tv2, NULL);
				if (tv2.tv_usec - tv1.tv_usec +
				    (tv2.tv_sec - tv1.tv_sec) * 1000000
				    > 500000) {
					kprintf("cpu %d idlelock %08x %08x\n",
						gd->mi.gd_cpuid,
						gd->mi.gd_reqflags,
						gd->gd_fpending);
				}
#endif
			}
		} else {
			splz();
			__asm __volatile("pause");
		}
	}
}

/*
 * Called by the spinlock code with or without a critical section held
 * when a spinlock is found to be seriously constested.
 *
 * We need to enter a critical section to prevent signals from recursing
 * into pthreads.
 */
void
cpu_spinlock_contested(void)
{
	cpu_pause();
}

/*
 * Clear registers on exec
 */
void
exec_setregs(u_long entry, u_long stack, u_long ps_strings)
{
	struct thread *td = curthread;
	struct lwp *lp = td->td_lwp;
	struct pcb *pcb = td->td_pcb;
	struct trapframe *regs = lp->lwp_md.md_regs;

	user_ldt_free(pcb);

	bzero((char *)regs, sizeof(struct trapframe));
	regs->tf_rip = entry;
	regs->tf_rsp = ((stack - 8) & ~0xFul) + 8; /* align the stack */
	regs->tf_rdi = stack;		/* argv */
	regs->tf_rflags = PSL_USER | (regs->tf_rflags & PSL_T);
	regs->tf_ss = _udatasel;
	regs->tf_cs = _ucodesel;
	regs->tf_rbx = ps_strings;

	/*
	 * Reset the hardware debug registers if they were in use.
	 * They won't have any meaning for the newly exec'd process.
	 */
	if (pcb->pcb_flags & PCB_DBREGS) {
		pcb->pcb_dr0 = 0;
		pcb->pcb_dr1 = 0;
		pcb->pcb_dr2 = 0;
		pcb->pcb_dr3 = 0;
		pcb->pcb_dr6 = 0;
		pcb->pcb_dr7 = 0; /* JG set bit 10? */
		if (pcb == td->td_pcb) {
			/*
			 * Clear the debug registers on the running
			 * CPU, otherwise they will end up affecting
			 * the next process we switch to.
			 */
			reset_dbregs();
		}
		pcb->pcb_flags &= ~PCB_DBREGS;
	}

	/*
	 * Initialize the math emulator (if any) for the current process.
	 * Actually, just clear the bit that says that the emulator has
	 * been initialized.  Initialization is delayed until the process
	 * traps to the emulator (if it is done at all) mainly because
	 * emulators don't provide an entry point for initialization.
	 */
	pcb->pcb_flags &= ~FP_SOFTFP;

	/*
	 * NOTE: do not set CR0_TS here.  npxinit() must do it after clearing
	 *	 gd_npxthread.  Otherwise a preemptive interrupt thread
	 *	 may panic in npxdna().
	 */
	crit_enter();
#if 0
	load_cr0(rcr0() | CR0_MP);
#endif

	/*
	 * NOTE: The MSR values must be correct so we can return to
	 *	 userland.  gd_user_fs/gs must be correct so the switch
	 *	 code knows what the current MSR values are.
	 */
	pcb->pcb_fsbase = 0;	/* Values loaded from PCB on switch */
	pcb->pcb_gsbase = 0;
	/* Initialize the npx (if any) for the current process. */
	npxinit();
	crit_exit();

	/*
	 * note: linux emulator needs edx to be 0x0 on entry, which is
	 * handled in execve simply by setting the 64 bit syscall
	 * return value to 0.
	 */
}

void
cpu_setregs(void)
{
#if 0
	unsigned int cr0;

	cr0 = rcr0();
	cr0 |= CR0_NE;			/* Done by npxinit() */
	cr0 |= CR0_MP | CR0_TS;		/* Done at every execve() too. */
	cr0 |= CR0_WP | CR0_AM;
	load_cr0(cr0);
	load_gs(_udatasel);
#endif
}

static int
sysctl_machdep_adjkerntz(SYSCTL_HANDLER_ARGS)
{
	int error;
	error = sysctl_handle_int(oidp, oidp->oid_arg1, oidp->oid_arg2,
		req);
	if (!error && req->newptr)
		resettodr();
	return (error);
}

SYSCTL_PROC(_machdep, CPU_ADJKERNTZ, adjkerntz, CTLTYPE_INT|CTLFLAG_RW,
	&adjkerntz, 0, sysctl_machdep_adjkerntz, "I", "");

/*
 * Initialize x86 and configure to run kernel
 */

/*
 * Initialize segments & interrupt table
 */

extern  struct user *proc0paddr;

#if 0

extern inthand_t
	IDTVEC(div), IDTVEC(dbg), IDTVEC(nmi), IDTVEC(bpt), IDTVEC(ofl),
	IDTVEC(bnd), IDTVEC(ill), IDTVEC(dna), IDTVEC(fpusegm),
	IDTVEC(tss), IDTVEC(missing), IDTVEC(stk), IDTVEC(prot),
	IDTVEC(page), IDTVEC(mchk), IDTVEC(rsvd), IDTVEC(fpu), IDTVEC(align),
	IDTVEC(xmm), IDTVEC(dblfault),
	IDTVEC(fast_syscall), IDTVEC(fast_syscall32);
#endif

int
ptrace_set_pc(struct lwp *lp, unsigned long addr)
{
	lp->lwp_md.md_regs->tf_rip = addr;
	return (0);
}

int
ptrace_single_step(struct lwp *lp)
{
	lp->lwp_md.md_regs->tf_rflags |= PSL_T;
	return (0);
}

int
fill_regs(struct lwp *lp, struct reg *regs)
{
	struct trapframe *tp;

	if ((tp = lp->lwp_md.md_regs) == NULL)
		return EINVAL;
	bcopy(&tp->tf_rdi, &regs->r_rdi, sizeof(*regs));
	return (0);
}

int
set_regs(struct lwp *lp, struct reg *regs)
{
	struct trapframe *tp;

	tp = lp->lwp_md.md_regs;
	if (!EFL_SECURE(regs->r_rflags, tp->tf_rflags) ||
	    !CS_SECURE(regs->r_cs))
		return (EINVAL);
	bcopy(&regs->r_rdi, &tp->tf_rdi, sizeof(*regs));
	return (0);
}

static void
fill_fpregs_xmm(struct savexmm *sv_xmm, struct save87 *sv_87)
{
	struct env87 *penv_87 = &sv_87->sv_env;
	struct envxmm *penv_xmm = &sv_xmm->sv_env;
	int i;

	/* FPU control/status */
	penv_87->en_cw = penv_xmm->en_cw;
	penv_87->en_sw = penv_xmm->en_sw;
	penv_87->en_tw = penv_xmm->en_tw;
	penv_87->en_fip = penv_xmm->en_fip;
	penv_87->en_fcs = penv_xmm->en_fcs;
	penv_87->en_opcode = penv_xmm->en_opcode;
	penv_87->en_foo = penv_xmm->en_foo;
	penv_87->en_fos = penv_xmm->en_fos;

	/* FPU registers */
	for (i = 0; i < 8; ++i)
		sv_87->sv_ac[i] = sv_xmm->sv_fp[i].fp_acc;
}

static void
set_fpregs_xmm(struct save87 *sv_87, struct savexmm *sv_xmm)
{
	struct env87 *penv_87 = &sv_87->sv_env;
	struct envxmm *penv_xmm = &sv_xmm->sv_env;
	int i;

	/* FPU control/status */
	penv_xmm->en_cw = penv_87->en_cw;
	penv_xmm->en_sw = penv_87->en_sw;
	penv_xmm->en_tw = penv_87->en_tw;
	penv_xmm->en_fip = penv_87->en_fip;
	penv_xmm->en_fcs = penv_87->en_fcs;
	penv_xmm->en_opcode = penv_87->en_opcode;
	penv_xmm->en_foo = penv_87->en_foo;
	penv_xmm->en_fos = penv_87->en_fos;

	/* FPU registers */
	for (i = 0; i < 8; ++i)
		sv_xmm->sv_fp[i].fp_acc = sv_87->sv_ac[i];
}

int
fill_fpregs(struct lwp *lp, struct fpreg *fpregs)
{
	if (lp->lwp_thread == NULL || lp->lwp_thread->td_pcb == NULL)
		return EINVAL;
	if (cpu_fxsr) {
		fill_fpregs_xmm(&lp->lwp_thread->td_pcb->pcb_save.sv_xmm,
				(struct save87 *)fpregs);
		return (0);
	}
	bcopy(&lp->lwp_thread->td_pcb->pcb_save.sv_87, fpregs, sizeof *fpregs);
	return (0);
}

int
set_fpregs(struct lwp *lp, struct fpreg *fpregs)
{
	if (cpu_fxsr) {
		set_fpregs_xmm((struct save87 *)fpregs,
			       &lp->lwp_thread->td_pcb->pcb_save.sv_xmm);
		return (0);
	}
	bcopy(fpregs, &lp->lwp_thread->td_pcb->pcb_save.sv_87, sizeof *fpregs);
	return (0);
}

int
fill_dbregs(struct lwp *lp, struct dbreg *dbregs)
{
	return (ENOSYS);
}

int
set_dbregs(struct lwp *lp, struct dbreg *dbregs)
{
	return (ENOSYS);
}

#if 0
/*
 * Return > 0 if a hardware breakpoint has been hit, and the
 * breakpoint was in user space.  Return 0, otherwise.
 */
int
user_dbreg_trap(void)
{
        u_int32_t dr7, dr6; /* debug registers dr6 and dr7 */
        u_int32_t bp;       /* breakpoint bits extracted from dr6 */
        int nbp;            /* number of breakpoints that triggered */
        caddr_t addr[4];    /* breakpoint addresses */
        int i;

        dr7 = rdr7();
        if ((dr7 & 0x000000ff) == 0) {
                /*
                 * all GE and LE bits in the dr7 register are zero,
                 * thus the trap couldn't have been caused by the
                 * hardware debug registers
                 */
                return 0;
        }

        nbp = 0;
        dr6 = rdr6();
        bp = dr6 & 0x0000000f;

        if (!bp) {
                /*
                 * None of the breakpoint bits are set meaning this
                 * trap was not caused by any of the debug registers
                 */
                return 0;
        }

        /*
         * at least one of the breakpoints were hit, check to see
         * which ones and if any of them are user space addresses
         */

        if (bp & 0x01) {
                addr[nbp++] = (caddr_t)rdr0();
        }
        if (bp & 0x02) {
                addr[nbp++] = (caddr_t)rdr1();
        }
        if (bp & 0x04) {
                addr[nbp++] = (caddr_t)rdr2();
        }
        if (bp & 0x08) {
                addr[nbp++] = (caddr_t)rdr3();
        }

        for (i=0; i<nbp; i++) {
                if (addr[i] <
                    (caddr_t)VM_MAX_USER_ADDRESS) {
                        /*
                         * addr[i] is in user space
                         */
                        return nbp;
                }
        }

        /*
         * None of the breakpoints are in user space.
         */
        return 0;
}

#endif

void
identcpu(void)
{
	int regs[4];

	do_cpuid(1, regs);
	cpu_feature = regs[3];
}


#ifndef DDB
void
Debugger(const char *msg)
{
	kprintf("Debugger(\"%s\") called.\n", msg);
}
#endif /* no DDB */
