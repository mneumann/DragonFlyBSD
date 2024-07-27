/*
 * Copyright (c) 1996, by Steve Passe
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. The name of the developer may NOT be used to endorse or promote products
 *    derived from this software without specific prior written permission.
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
 *
 * $FreeBSD: src/sys/i386/i386/mp_machdep.c,v 1.115.2.15 2003/03/14 21:22:35 jhb Exp $
 */

#include "opt_cpu.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/sysctl.h>
#include <sys/malloc.h>
#include <sys/memrange.h>
#include <sys/cons.h>	/* cngetc() */
#include <sys/machintr.h>
#include <sys/cpu_topology.h>

#include <sys/mplock2.h>

#include <vm/vm.h>
#include <vm/vm_param.h>
#include <vm/pmap.h>
#include <vm/vm_kern.h>
#include <vm/vm_extern.h>
#include <sys/lock.h>
#include <vm/vm_map.h>

#include <machine/smp.h>
#include <machine_base/apic/apicreg.h>
#include <machine/atomic.h>
#include <machine/cpufunc.h>
#include <machine/cputypes.h>
#include <machine_base/apic/lapic.h>
#include <machine_base/apic/ioapic.h>
#include <machine_base/acpica/acpi_md_cpu.h>
#include <machine/psl.h>
#include <machine/segments.h>
#include <machine/tss.h>
#include <machine/specialreg.h>
#include <machine/globaldata.h>
#include <machine/pmap_inval.h>
#include <machine/clock.h>

#include <machine/md_var.h>		/* setidt() */
#include <machine_base/icu/icu.h>	/* IPIs */
#include <machine_base/icu/icu_var.h>
#include <machine_base/apic/ioapic_abi.h>
#include <machine/intr_machdep.h>	/* IPIs */

#define WARMBOOT_TARGET		0
#define WARMBOOT_OFF		(KERNBASE + 0x0467)
#define WARMBOOT_SEG		(KERNBASE + 0x0469)

#define CMOS_REG		(0x70)
#define CMOS_DATA		(0x71)
#define BIOS_RESET		(0x0f)
#define BIOS_WARM		(0x0a)

#define INVLPG_TIMEOUT_DEFAULT	10
#define INVLPG_TIMEOUT_VM	60

/*
 * this code MUST be enabled here and in mpboot.s.
 * it follows the very early stages of AP boot by placing values in CMOS ram.
 * it NORMALLY will never be needed and thus the primitive method for enabling.
 *
 */
#if defined(CHECK_POINTS)
#define CHECK_READ(A)	 (outb(CMOS_REG, (A)), inb(CMOS_DATA))
#define CHECK_WRITE(A,D) (outb(CMOS_REG, (A)), outb(CMOS_DATA, (D)))

#define CHECK_INIT(D);				\
	CHECK_WRITE(0x34, (D));			\
	CHECK_WRITE(0x35, (D));			\
	CHECK_WRITE(0x36, (D));			\
	CHECK_WRITE(0x37, (D));			\
	CHECK_WRITE(0x38, (D));			\
	CHECK_WRITE(0x39, (D));

#define CHECK_PRINT(S);				\
	kprintf("%s: %d, %d, %d, %d, %d, %d\n",	\
	   (S),					\
	   CHECK_READ(0x34),			\
	   CHECK_READ(0x35),			\
	   CHECK_READ(0x36),			\
	   CHECK_READ(0x37),			\
	   CHECK_READ(0x38),			\
	   CHECK_READ(0x39));

#else				/* CHECK_POINTS */

#define CHECK_INIT(D)
#define CHECK_PRINT(S)

#endif				/* CHECK_POINTS */

/*
 * Values to send to the POST hardware.
 */
#define MP_BOOTADDRESS_POST	0x10
#define MP_PROBE_POST		0x11
#define MPTABLE_PASS1_POST	0x12

#define MP_START_POST		0x13
#define MP_ENABLE_POST		0x14
#define MPTABLE_PASS2_POST	0x15

#define START_ALL_APS_POST	0x16
#define INSTALL_AP_TRAMP_POST	0x17
#define START_AP_POST		0x18

#define MP_ANNOUNCE_POST	0x19

/** XXX FIXME: where does this really belong, isa.h/isa.c perhaps? */
int	current_postcode;

/** XXX FIXME: what system files declare these??? */

extern int naps;
extern int _udatasel;

int64_t tsc0_offset;
extern int64_t tsc_offsets[];

/* AP uses this during bootstrap.  Do not staticize.  */
char *bootSTK;
static int bootAP;

struct pcb stoppcbs[MAXCPU];

extern inthand_t IDTVEC(fast_syscall), IDTVEC(fast_syscall32);

/*
 * Local data and functions.
 */

static u_int	boot_address;
static int	mp_finish;
static int	mp_finish_lapic;

static int	start_all_aps(u_int boot_addr);
#if 0
static void	install_ap_tramp(u_int boot_addr);
#endif
static int	start_ap(struct mdglobaldata *gd, u_int boot_addr, int smibest);
static int	smitest(void);
static void	mp_bsp_simple_setup(void);

/* which cpus have been started */
__read_mostly static cpumask_t smp_startup_mask = CPUMASK_INITIALIZER_ONLYONE;
/* which cpus have lapic been inited */
__read_mostly static cpumask_t smp_lapic_mask = CPUMASK_INITIALIZER_ONLYONE;
/* which cpus are ready for IPIs etc? */
__read_mostly cpumask_t smp_active_mask = CPUMASK_INITIALIZER_ONLYONE;
__read_mostly cpumask_t smp_finalize_mask = CPUMASK_INITIALIZER_ONLYONE;

SYSCTL_OPAQUE(_machdep, OID_AUTO, smp_active, CTLFLAG_RD,
	      &smp_active_mask, sizeof(smp_active_mask), "LU", "");
static u_int	bootMP_size;
__read_mostly static u_int	report_invlpg_src;
SYSCTL_INT(_machdep, OID_AUTO, report_invlpg_src, CTLFLAG_RW,
	&report_invlpg_src, 0, "");
__read_mostly static u_int	report_invltlb_src;
SYSCTL_INT(_machdep, OID_AUTO, report_invltlb_src, CTLFLAG_RW,
	&report_invltlb_src, 0, "");
__read_mostly static int	optimized_invltlb;
SYSCTL_INT(_machdep, OID_AUTO, optimized_invltlb, CTLFLAG_RW,
	&optimized_invltlb, 0, "");
__read_mostly static int	all_but_self_ipi_enable = 1;
SYSCTL_INT(_machdep, OID_AUTO, all_but_self_ipi_enable, CTLFLAG_RW,
	&all_but_self_ipi_enable, 0, "");
__read_mostly static int	invlpg_timeout = INVLPG_TIMEOUT_DEFAULT;
SYSCTL_INT(_machdep, OID_AUTO, invlpg_timeout, CTLFLAG_RW,
	&invlpg_timeout, 0, "");

/* Local data for detecting CPU TOPOLOGY */
static int core_bits = 0;
static int logical_CPU_bits = 0;


/*
 * Calculate usable address in base memory for AP trampoline code.
 */
u_int
mp_bootaddress(u_int basemem)
{
	POSTCODE(MP_BOOTADDRESS_POST);

	bootMP_size = mptramp_end - mptramp_start;
	boot_address = trunc_page(basemem * 1024); /* round down to 4k boundary */
	if (((basemem * 1024) - boot_address) < bootMP_size)
		boot_address -= PAGE_SIZE;	/* not enough, lower by 4k */
	/* 3 levels of page table pages */
	mptramp_pagetables = boot_address - (PAGE_SIZE * 3);

	return mptramp_pagetables;
}

/*
 * Print various information about the SMP system hardware and setup.
 */
void
mp_announce(void)
{
	int     x;

	POSTCODE(MP_ANNOUNCE_POST);

	kprintf("DragonFly/MP: Multiprocessor motherboard\n");
	kprintf(" cpu0 (BSP): apic id: %2d\n", CPUID_TO_APICID(0));
	for (x = 1; x <= naps; ++x)
		kprintf(" cpu%d (AP):  apic id: %2d\n", x, CPUID_TO_APICID(x));

	if (!ioapic_enable)
		kprintf(" Warning: APIC I/O disabled\n");
}

/*
 * AP cpu's call this to sync up protected mode.
 *
 * WARNING! %gs is not set up on entry.  This routine sets up %gs.
 */
void
init_secondary(void)
{
	int	gsel_tss;
	int	x, myid = bootAP;
	u_int64_t msr, cr0;
	struct mdglobaldata *md;
	struct privatespace *ps;
	struct user_segment_descriptor *gdt;

	ps = CPU_prvspace[myid];
	gdt = ps->mdglobaldata.gd_gdt;

	gdt_segs[GPROC0_SEL].ssd_base = (long)&ps->common_tss;
	ps->mdglobaldata.mi.gd_prvspace = ps;

	/* We fill the 32-bit segment descriptors */
	for (x = 0; x < NGDT; x++) {
		if (x != GPROC0_SEL && x != (GPROC0_SEL + 1))
			ssdtosd(&gdt_segs[x], &gdt[x]);
	}
	/* And now a 64-bit one */
	ssdtosyssd(&gdt_segs[GPROC0_SEL],
	    (struct system_segment_descriptor *)&gdt[GPROC0_SEL]);

	r_gdt.rd_limit = MAXGDT_LIMIT - 1;
	r_gdt.rd_base = (long)(intptr_t)gdt;
	lgdt(&r_gdt);			/* does magic intra-segment return */

	/* lgdt() destroys the GSBASE value, so we load GSBASE after lgdt() */
	wrmsr(MSR_FSBASE, 0);		/* User value */
	wrmsr(MSR_GSBASE, (u_int64_t)ps);
	wrmsr(MSR_KGSBASE, 0);		/* XXX User value while we're in the kernel */

	lidt(&r_idt_arr[mdcpu->mi.gd_cpuid]);

	load_ds(_udatasel);
	load_es(_udatasel);
	load_fs(_udatasel);

#if 0
	lldt(_default_ldt);
	mdcpu->gd_currentldt = _default_ldt;
#endif

	gsel_tss = GSEL(GPROC0_SEL, SEL_KPL);
	gdt[GPROC0_SEL].sd_type = SDT_SYSTSS;

	md = mdcpu;	/* loaded through %gs:0 (mdglobaldata.mi.gd_prvspace)*/

	/*
	 * TSS entry point for interrupts, traps, and exceptions
	 * (sans NMI).  This will always go to near the top of the pcpu
	 * trampoline area.  Hardware-pushed data will be copied into
	 * the trap-frame on entry, and (if necessary) returned to the
	 * trampoline on exit.
	 *
	 * We store some pcb data for the trampoline code above the
	 * stack the cpu hw pushes into, and arrange things so the
	 * address of tr_pcb_rsp is the same as the desired top of
	 * stack.
	 */
	ps->common_tss.tss_rsp0 = (register_t)&ps->trampoline.tr_pcb_rsp;
	ps->trampoline.tr_pcb_rsp = ps->common_tss.tss_rsp0;
	ps->trampoline.tr_pcb_gs_kernel = (register_t)md;
	ps->trampoline.tr_pcb_cr3 = KPML4phys;	/* adj to user cr3 live */
	ps->dbltramp.tr_pcb_gs_kernel = (register_t)md;
	ps->dbltramp.tr_pcb_cr3 = KPML4phys;
	ps->dbgtramp.tr_pcb_gs_kernel = (register_t)md;
	ps->dbgtramp.tr_pcb_cr3 = KPML4phys;

#if 0 /* JG XXX */
	ps->common_tss.tss_ioopt = (sizeof ps->common_tss) << 16;
#endif
	md->gd_tss_gdt = &gdt[GPROC0_SEL];
	md->gd_common_tssd = *md->gd_tss_gdt;

	/* double fault stack */
	ps->common_tss.tss_ist1 = (register_t)&ps->dbltramp.tr_pcb_rsp;
	ps->common_tss.tss_ist2 = (register_t)&ps->dbgtramp.tr_pcb_rsp;

	ltr(gsel_tss);

	/*
	 * Set to a known state:
	 * Set by mpboot.s: CR0_PG, CR0_PE
	 * Set by cpu_setregs: CR0_NE, CR0_MP, CR0_TS, CR0_WP, CR0_AM
	 */
	cr0 = rcr0();
	cr0 &= ~(CR0_CD | CR0_NW | CR0_EM);
	load_cr0(cr0);

	/* Set up the fast syscall stuff */
	msr = rdmsr(MSR_EFER) | EFER_SCE;
	wrmsr(MSR_EFER, msr);
	wrmsr(MSR_LSTAR, (u_int64_t)IDTVEC(fast_syscall));
	wrmsr(MSR_CSTAR, (u_int64_t)IDTVEC(fast_syscall32));
	msr = ((u_int64_t)GSEL(GCODE_SEL, SEL_KPL) << 32) |
	      ((u_int64_t)GSEL(GUCODE32_SEL, SEL_UPL) << 48);
	wrmsr(MSR_STAR, msr);
	wrmsr(MSR_SF_MASK, PSL_NT|PSL_T|PSL_I|PSL_C|PSL_D|PSL_IOPL|PSL_AC);

	pmap_set_opt();		/* PSE/4MB pages, etc */
	pmap_init_pat();	/* Page Attribute Table */

	/* set up CPU registers and state */
	cpu_setregs();

	/* set up SSE/NX registers */
	initializecpu(myid);

	/* set up FPU state on the AP */
	npxinit();

	/* If BSP is in the X2APIC mode, put the AP into the X2APIC mode. */
	if (x2apic_enable)
		lapic_x2apic_enter(FALSE);

	/* disable the APIC, just to be SURE */
	LAPIC_WRITE(svr, (LAPIC_READ(svr) & ~APIC_SVR_ENABLE));
}

/*******************************************************************
 * local functions and data
 */

/*
 * Start the SMP system
 */
static void
mp_start_aps(void *dummy __unused)
{
	if (lapic_enable) {
		/* start each Application Processor */
		start_all_aps(boot_address);
	} else {
		mp_bsp_simple_setup();
	}
}
SYSINIT(startaps, SI_BOOT2_START_APS, SI_ORDER_FIRST, mp_start_aps, NULL);

/*
 * start each AP in our list
 */
static int
start_all_aps(u_int boot_addr)
{
	vm_offset_t va = boot_address + KERNBASE;
	u_int64_t *pt4, *pt3, *pt2;
	int	pssize;
	int     x, i;
	int	shift;
	int	smicount;
	int	smibest;
	int	smilast;
	u_char  mpbiosreason;
	u_long  mpbioswarmvec;
	struct mdglobaldata *gd;
	struct privatespace *ps;
	size_t ipiq_size;

	POSTCODE(START_ALL_APS_POST);

	/* install the AP 1st level boot code */
	pmap_kenter(va, boot_address);
	cpu_invlpg((void *)va);		/* JG XXX */
	bcopy(mptramp_start, (void *)va, bootMP_size);

	/* Locate the page tables, they'll be below the trampoline */
	pt4 = (u_int64_t *)(uintptr_t)(mptramp_pagetables + KERNBASE);
	pt3 = pt4 + (PAGE_SIZE) / sizeof(u_int64_t);
	pt2 = pt3 + (PAGE_SIZE) / sizeof(u_int64_t);

	/* Create the initial 1GB replicated page tables */
	for (i = 0; i < 512; i++) {
		/* Each slot of the level 4 pages points to the same level 3 page */
		pt4[i] = (u_int64_t)(uintptr_t)(mptramp_pagetables + PAGE_SIZE);
		pt4[i] |= kernel_pmap->pmap_bits[PG_V_IDX] |
		    kernel_pmap->pmap_bits[PG_RW_IDX] |
		    kernel_pmap->pmap_bits[PG_U_IDX];

		/* Each slot of the level 3 pages points to the same level 2 page */
		pt3[i] = (u_int64_t)(uintptr_t)(mptramp_pagetables + (2 * PAGE_SIZE));
		pt3[i] |= kernel_pmap->pmap_bits[PG_V_IDX] |
		    kernel_pmap->pmap_bits[PG_RW_IDX] |
		    kernel_pmap->pmap_bits[PG_U_IDX];

		/* The level 2 page slots are mapped with 2MB pages for 1GB. */
		pt2[i] = i * (2 * 1024 * 1024);
		pt2[i] |= kernel_pmap->pmap_bits[PG_V_IDX] |
		    kernel_pmap->pmap_bits[PG_RW_IDX] |
		    kernel_pmap->pmap_bits[PG_PS_IDX] |
		    kernel_pmap->pmap_bits[PG_U_IDX];
	}

	/* save the current value of the warm-start vector */
	mpbioswarmvec = *((u_int32_t *) WARMBOOT_OFF);
	outb(CMOS_REG, BIOS_RESET);
	mpbiosreason = inb(CMOS_DATA);

	/* setup a vector to our boot code */
	*((volatile u_short *) WARMBOOT_OFF) = WARMBOOT_TARGET;
	*((volatile u_short *) WARMBOOT_SEG) = (boot_address >> 4);
	outb(CMOS_REG, BIOS_RESET);
	outb(CMOS_DATA, BIOS_WARM);	/* 'warm-start' */

	/*
	 * If we have a TSC we can figure out the SMI interrupt rate.
	 * The SMI does not necessarily use a constant rate.  Spend
	 * up to 250ms trying to figure it out.
	 */
	smibest = 0;
	if (cpu_feature & CPUID_TSC) {
		set_apic_timer(275000);
		smilast = read_apic_timer();
		for (x = 0; x < 20 && read_apic_timer(); ++x) {
			smicount = smitest();
			if (smibest == 0 || smilast - smicount < smibest)
				smibest = smilast - smicount;
			smilast = smicount;
		}
		if (smibest > 250000)
			smibest = 0;
	}
	if (smibest)
		kprintf("SMI Frequency (worst case): %d Hz (%d us)\n",
			1000000 / smibest, smibest);

	/*
	 * This is nasty but if we are a guest in a virtual machine,
	 * give the smpinvl synchronization code up to 60 seconds
	 */

	if (vmm_guest != VMM_GUEST_NONE)
		invlpg_timeout = INVLPG_TIMEOUT_VM;

	/* start each AP */
	for (x = 1; x <= naps; ++x) {
		/* This is a bit verbose, it will go away soon.  */

		pssize = sizeof(struct privatespace);
		ps = (void *)
			kmem_alloc3(kernel_map, pssize, VM_SUBSYS_GD,
				    KM_CPU(x));
		bzero(ps, pssize);
		CPU_prvspace[x] = ps;
		gd = &ps->mdglobaldata;
		gd->mi.gd_prvspace = ps;
		gd->gd_gdt = (void *)
			kmem_alloc3(kernel_map, MAXGDT_LIMIT, VM_SUBSYS_GD,
				    KM_CPU(x));
		bzero(gd->gd_gdt, MAXGDT_LIMIT);

#if 0
		kprintf("ps %d %p %d\n", x, ps, pssize);
#endif

		/* prime data page for it to use */
		mi_gdinit(&gd->mi, x);
		cpu_gdinit(gd, x);
		ipiq_size = sizeof(struct lwkt_ipiq) * (naps + 1);
		gd->mi.gd_ipiq = (void *)kmem_alloc3(kernel_map, ipiq_size,
						     VM_SUBSYS_IPIQ, KM_CPU(x));
		bzero(gd->mi.gd_ipiq, ipiq_size);

		gd->gd_acpi_id = CPUID_TO_ACPIID(gd->mi.gd_cpuid);

		/* initialize arc4random. */
		arc4_init_pcpu(x);

		/* setup a vector to our boot code */
		*((volatile u_short *) WARMBOOT_OFF) = WARMBOOT_TARGET;
		*((volatile u_short *) WARMBOOT_SEG) = (boot_addr >> 4);
		outb(CMOS_REG, BIOS_RESET);
		outb(CMOS_DATA, BIOS_WARM);	/* 'warm-start' */

		/*
		 * Setup the AP boot stack
		 */
		bootSTK = &ps->idlestack[UPAGES * PAGE_SIZE - PAGE_SIZE];
		bootAP = x;

		/* attempt to start the Application Processor */
		CHECK_INIT(99);	/* setup checkpoints */
		if (!start_ap(gd, boot_addr, smibest)) {
			kprintf("\nAP #%d (PHY# %d) failed!\n",
				x, CPUID_TO_APICID(x));
			CHECK_PRINT("trace");	/* show checkpoints */
			/* better panic as the AP may be running loose */
			kprintf("panic y/n? [y] ");
			cnpoll(TRUE);
			if (cngetc() != 'n')
				panic("bye-bye");
			cnpoll(FALSE);
		}
		CHECK_PRINT("trace");		/* show checkpoints */
	}

	/* set ncpus to 1 + highest logical cpu.  Not all may have come up */
	ncpus = x;

	for (shift = 0; (1 << shift) <= ncpus; ++shift)
		;
	--shift;

	/* ncpus_fit -- ncpus rounded up to the nearest power of 2 */
	if ((1 << shift) < ncpus)
		++shift;
	ncpus_fit = 1 << shift;
	ncpus_fit_mask = ncpus_fit - 1;

	/* build our map of 'other' CPUs */
	mycpu->gd_other_cpus = smp_startup_mask;
	CPUMASK_NANDBIT(mycpu->gd_other_cpus, mycpu->gd_cpuid);

	malloc_reinit_ncpus();

	gd = (struct mdglobaldata *)mycpu;
	gd->gd_acpi_id = CPUID_TO_ACPIID(mycpu->gd_cpuid);

	ipiq_size = sizeof(struct lwkt_ipiq) * ncpus;
	mycpu->gd_ipiq = (void *)kmem_alloc3(kernel_map, ipiq_size,
					     VM_SUBSYS_IPIQ, KM_CPU(0));
	bzero(mycpu->gd_ipiq, ipiq_size);

	/* initialize arc4random. */
	arc4_init_pcpu(0);

	/* restore the warmstart vector */
	*(u_long *) WARMBOOT_OFF = mpbioswarmvec;
	outb(CMOS_REG, BIOS_RESET);
	outb(CMOS_DATA, mpbiosreason);

	/*
	 * NOTE!  The idlestack for the BSP was setup by locore.  Finish
	 * up, clean out the P==V mapping we did earlier.
	 */
	pmap_set_opt();

	/*
	 * Wait all APs to finish initializing LAPIC
	 */
	if (bootverbose)
		kprintf("SMP: Waiting APs LAPIC initialization\n");
	if (cpu_feature & CPUID_TSC)
		tsc0_offset = rdtsc();
	tsc_offsets[0] = 0;
	mp_finish_lapic = 1;
	rel_mplock();

	while (CPUMASK_CMPMASKNEQ(smp_lapic_mask, smp_startup_mask)) {
		cpu_pause();
		cpu_lfence();
		if (cpu_feature & CPUID_TSC)
			tsc0_offset = rdtsc();
	}
	while (try_mplock() == 0) {
		cpu_pause();
		cpu_lfence();
	}

	/* number of APs actually started */
	return ncpus - 1;
}


/*
 * load the 1st level AP boot code into base memory.
 */

/* targets for relocation */
extern void bigJump(void);
extern void bootCodeSeg(void);
extern void bootDataSeg(void);
extern void MPentry(void);
extern u_int MP_GDT;
extern u_int mp_gdtbase;

#if 0

static void
install_ap_tramp(u_int boot_addr)
{
	int     x;
	int     size = *(int *) ((u_long) & bootMP_size);
	u_char *src = (u_char *) ((u_long) bootMP);
	u_char *dst = (u_char *) boot_addr + KERNBASE;
	u_int   boot_base = (u_int) bootMP;
	u_int8_t *dst8;
	u_int16_t *dst16;
	u_int32_t *dst32;

	POSTCODE(INSTALL_AP_TRAMP_POST);

	for (x = 0; x < size; ++x)
		*dst++ = *src++;

	/*
	 * modify addresses in code we just moved to basemem. unfortunately we
	 * need fairly detailed info about mpboot.s for this to work.  changes
	 * to mpboot.s might require changes here.
	 */

	/* boot code is located in KERNEL space */
	dst = (u_char *) boot_addr + KERNBASE;

	/* modify the lgdt arg */
	dst32 = (u_int32_t *) (dst + ((u_int) & mp_gdtbase - boot_base));
	*dst32 = boot_addr + ((u_int) & MP_GDT - boot_base);

	/* modify the ljmp target for MPentry() */
	dst32 = (u_int32_t *) (dst + ((u_int) bigJump - boot_base) + 1);
	*dst32 = ((u_int) MPentry - KERNBASE);

	/* modify the target for boot code segment */
	dst16 = (u_int16_t *) (dst + ((u_int) bootCodeSeg - boot_base));
	dst8 = (u_int8_t *) (dst16 + 1);
	*dst16 = (u_int) boot_addr & 0xffff;
	*dst8 = ((u_int) boot_addr >> 16) & 0xff;

	/* modify the target for boot data segment */
	dst16 = (u_int16_t *) (dst + ((u_int) bootDataSeg - boot_base));
	dst8 = (u_int8_t *) (dst16 + 1);
	*dst16 = (u_int) boot_addr & 0xffff;
	*dst8 = ((u_int) boot_addr >> 16) & 0xff;
}

#endif

/*
 * This function starts the AP (application processor) identified
 * by the APIC ID 'physicalCpu'.  It does quite a "song and dance"
 * to accomplish this.  This is necessary because of the nuances
 * of the different hardware we might encounter.  It ain't pretty,
 * but it seems to work.
 *
 * NOTE: eventually an AP gets to ap_init(), which is called just 
 * before the AP goes into the LWKT scheduler's idle loop.
 */
static int
start_ap(struct mdglobaldata *gd, u_int boot_addr, int smibest)
{
	int     physical_cpu;
	int     vector;

	POSTCODE(START_AP_POST);

	/* get the PHYSICAL APIC ID# */
	physical_cpu = CPUID_TO_APICID(gd->mi.gd_cpuid);

	/* calculate the vector */
	vector = (boot_addr >> 12) & 0xff;

	/* We don't want anything interfering */
	cpu_disable_intr();

	/* Make sure the target cpu sees everything */
	wbinvd();

	/*
	 * Try to detect when a SMI has occurred, wait up to 200ms.
	 *
	 * If a SMI occurs during an AP reset but before we issue
	 * the STARTUP command, the AP may brick.  To work around
	 * this problem we hold off doing the AP startup until
	 * after we have detected the SMI.  Hopefully another SMI
	 * will not occur before we finish the AP startup.
	 *
	 * Retries don't seem to help.  SMIs have a window of opportunity
	 * and if USB->legacy keyboard emulation is enabled in the BIOS
	 * the interrupt rate can be quite high.
	 *
	 * NOTE: Don't worry about the L1 cache load, it might bloat
	 *	 ldelta a little but ndelta will be so huge when the SMI
	 *	 occurs the detection logic will still work fine.
	 */
	if (smibest) {
		set_apic_timer(200000);
		smitest();
	}

	/*
	 * first we do an INIT/RESET IPI this INIT IPI might be run, reseting
	 * and running the target CPU. OR this INIT IPI might be latched (P5
	 * bug), CPU waiting for STARTUP IPI. OR this INIT IPI might be
	 * ignored.
	 *
	 * see apic/apicreg.h for icr bit definitions.
	 *
	 * TIME CRITICAL CODE, DO NOT DO ANY KPRINTFS IN THE HOT PATH.
	 */

	/*
	 * Do an INIT IPI: assert RESET
	 *
	 * Use edge triggered mode to assert INIT
	 */
	lapic_seticr_sync(physical_cpu,
	    APIC_DESTMODE_PHY |
	    APIC_DEST_DESTFLD |
	    APIC_TRIGMOD_EDGE |
	    APIC_LEVEL_ASSERT |
	    APIC_DELMODE_INIT);

	/*
	 * The spec calls for a 10ms delay but we may have to use a
	 * MUCH lower delay to avoid bricking an AP due to a fast SMI
	 * interrupt.  We have other loops here too and dividing by 2
	 * doesn't seem to be enough even after subtracting 350us,
	 * so we divide by 4.
	 *
	 * Our minimum delay is 150uS, maximum is 10ms.  If no SMI
	 * interrupt was detected we use the full 10ms.
	 */
	if (smibest == 0)
		u_sleep(10000);
	else if (smibest < 150 * 4 + 350)
		u_sleep(150);
	else if ((smibest - 350) / 4 < 10000)
		u_sleep((smibest - 350) / 4);
	else
		u_sleep(10000);

	/*
	 * Do an INIT IPI: deassert RESET
	 *
	 * Use level triggered mode to deassert.  It is unclear
	 * why we need to do this.
	 */
	lapic_seticr_sync(physical_cpu,
	    APIC_DESTMODE_PHY |
	    APIC_DEST_DESTFLD |
	    APIC_TRIGMOD_LEVEL |
	    APIC_LEVEL_DEASSERT |
	    APIC_DELMODE_INIT);
	u_sleep(150);				/* wait 150us */

	/*
	 * Next we do a STARTUP IPI: the previous INIT IPI might still be
	 * latched, (P5 bug) this 1st STARTUP would then terminate
	 * immediately, and the previously started INIT IPI would continue. OR
	 * the previous INIT IPI has already run. and this STARTUP IPI will
	 * run. OR the previous INIT IPI was ignored. and this STARTUP IPI
	 * will run.
	 *
	 * XXX set APIC_LEVEL_ASSERT
	 */
	lapic_seticr_sync(physical_cpu,
	    APIC_DESTMODE_PHY |
	    APIC_DEST_DESTFLD |
	    APIC_DELMODE_STARTUP |
	    vector);
	u_sleep(200);		/* wait ~200uS */

	/*
	 * Finally we do a 2nd STARTUP IPI: this 2nd STARTUP IPI should run IF
	 * the previous STARTUP IPI was cancelled by a latched INIT IPI. OR
	 * this STARTUP IPI will be ignored, as only ONE STARTUP IPI is
	 * recognized after hardware RESET or INIT IPI.
	 *
	 * XXX set APIC_LEVEL_ASSERT
	 */
	lapic_seticr_sync(physical_cpu,
	    APIC_DESTMODE_PHY |
	    APIC_DEST_DESTFLD |
	    APIC_DELMODE_STARTUP |
	    vector);

	/* Resume normal operation */
	cpu_enable_intr();

	/* wait for it to start, see ap_init() */
	set_apic_timer(5000000);/* == 5 seconds */
	while (read_apic_timer()) {
		if (CPUMASK_TESTBIT(smp_startup_mask, gd->mi.gd_cpuid))
			return 1;	/* return SUCCESS */
	}

	return 0;		/* return FAILURE */
}

static
int
smitest(void)
{
	int64_t	ltsc;
	int64_t	ntsc;
	int64_t	ldelta;
	int64_t	ndelta;
	int count;

	ldelta = 0;
	ndelta = 0;
	while (read_apic_timer()) {
		ltsc = rdtsc();
		for (count = 0; count < 100; ++count)
			ntsc = rdtsc();	/* force loop to occur */
		if (ldelta) {
			ndelta = ntsc - ltsc;
			if (ldelta > ndelta)
				ldelta = ndelta;
			if (ndelta > ldelta * 2)
				break;
		} else {
			ldelta = ntsc - ltsc;
		}
	}
	return(read_apic_timer());
}

/*
 * Synchronously flush the TLB on all other CPU's.  The current cpu's
 * TLB is not flushed.  If the caller wishes to flush the current cpu's
 * TLB the caller must call cpu_invltlb() in addition to smp_invltlb().
 *
 * This routine may be called concurrently from multiple cpus.  When this
 * happens, smp_invltlb() can wind up sticking around in the confirmation
 * while() loop at the end as additional cpus are added to the global
 * cpumask, until they are acknowledged by another IPI.
 *
 * NOTE: If for some reason we were unable to start all cpus we cannot
 *	 safely use broadcast IPIs.
 */

cpumask_t smp_smurf_mask;
static cpumask_t smp_invltlb_mask;
#define LOOPRECOVER
#define LOOPMASK_IN
#ifdef LOOPMASK_IN
cpumask_t smp_in_mask;
#endif
cpumask_t smp_invmask;
extern cpumask_t smp_idleinvl_mask;
extern cpumask_t smp_idleinvl_reqs;

/*
 * Atomically OR bits in *mask to smp_smurf_mask.  Adjust *mask to remove
 * bits that do not need to be IPId.  These bits are still part of the command,
 * but the target cpus have already been signalled and do not need to be
 * sigalled again.
 */
#include <sys/spinlock.h>
#include <sys/spinlock2.h>

static __noinline
void
smp_smurf_fetchset(cpumask_t *mask)
{
	cpumask_t omask;
	int i;
	__uint64_t obits;
	__uint64_t nbits;

	i = 0;
	while (i < CPUMASK_ELEMENTS) {
		obits = smp_smurf_mask.ary[i];
		cpu_ccfence();
		nbits = obits | mask->ary[i];
		if (atomic_cmpset_long(&smp_smurf_mask.ary[i], obits, nbits)) {
			omask.ary[i] = obits;
			++i;
		}
	}
	CPUMASK_NANDMASK(*mask, omask);
}

/*
 * This is a mechanism which guarantees that cpu_invltlb() will be executed
 * on idle cpus without having to signal or wake them up.  The invltlb will be
 * executed when they wake up, prior to any scheduling or interrupt thread.
 *
 * (*mask) is modified to remove the cpus we successfully negotiate this
 * function with.  This function may only be used with semi-synchronous
 * commands (typically invltlb's or semi-synchronous invalidations which
 * are usually associated only with kernel memory).
 */
void
smp_smurf_idleinvlclr(cpumask_t *mask)
{
	if (optimized_invltlb) {
		ATOMIC_CPUMASK_ORMASK(smp_idleinvl_reqs, *mask);
		/* cpu_lfence() not needed */
		CPUMASK_NANDMASK(*mask, smp_idleinvl_mask);
	}
}

/*
 * Issue cpu_invltlb() across all cpus except the current cpu.
 *
 * This function will arrange to avoid idle cpus, but still guarantee that
 * invltlb is run on them when they wake up prior to any scheduling or
 * nominal interrupt.
 */
void
smp_invltlb(void)
{
	struct mdglobaldata *md = mdcpu;
	cpumask_t mask;
	unsigned long rflags;
#ifdef LOOPRECOVER
	tsc_uclock_t tsc_base = rdtsc();
	int repeats = 0;
#endif

	if (report_invltlb_src > 0) {
		if (--report_invltlb_src <= 0)
			print_backtrace(8);
	}

	/*
	 * Disallow normal interrupts, set all active cpus except our own
	 * in the global smp_invltlb_mask.
	 */
	++md->mi.gd_cnt.v_smpinvltlb;
	crit_enter_gd(&md->mi);

	/*
	 * Bits we want to set in smp_invltlb_mask.  We do not want to signal
	 * our own cpu.  Also try to remove bits associated with idle cpus
	 * that we can flag for auto-invltlb.
	 */
	mask = smp_active_mask;
	CPUMASK_NANDBIT(mask, md->mi.gd_cpuid);
	smp_smurf_idleinvlclr(&mask);

	rflags = read_rflags();
	cpu_disable_intr();
	ATOMIC_CPUMASK_ORMASK(smp_invltlb_mask, mask);

	/*
	 * IPI non-idle cpus represented by mask.  The omask calculation
	 * removes cpus from the mask which already have a Xinvltlb IPI
	 * pending (avoid double-queueing the IPI).
	 *
	 * We must disable real interrupts when setting the smurf flags or
	 * we might race a XINVLTLB before we manage to send the ipi's for
	 * the bits we set.
	 *
	 * NOTE: We are not signalling ourselves, mask already does NOT
	 * include our own cpu.
	 */
	smp_smurf_fetchset(&mask);

	/*
	 * Issue the IPI.  Note that the XINVLTLB IPI runs regardless of
	 * the critical section count on the target cpus.
	 */
	CPUMASK_ORMASK(mask, md->mi.gd_cpumask);
	if (all_but_self_ipi_enable &&
	    (all_but_self_ipi_enable >= 2 ||
	     CPUMASK_CMPMASKEQ(smp_startup_mask, mask))) {
		all_but_self_ipi(XINVLTLB_OFFSET);
	} else {
		CPUMASK_NANDMASK(mask, md->mi.gd_cpumask);
		selected_apic_ipi(mask, XINVLTLB_OFFSET, APIC_DELMODE_FIXED);
	}

	/*
	 * Wait for acknowledgement by all cpus.  smp_inval_intr() will
	 * temporarily enable interrupts to avoid deadlocking the lapic,
	 * and will also handle running cpu_invltlb() and remote invlpg
	 * command son our cpu if some other cpu requests it of us.
	 *
	 * WARNING! I originally tried to implement this as a hard loop
	 *	    checking only smp_invltlb_mask (and issuing a local
	 *	    cpu_invltlb() if requested), with interrupts enabled
	 *	    and without calling smp_inval_intr().  This DID NOT WORK.
	 *	    It resulted in weird races where smurf bits would get
	 *	    cleared without any action being taken.
	 */
	smp_inval_intr();
	CPUMASK_ASSZERO(mask);
	while (CPUMASK_CMPMASKNEQ(smp_invltlb_mask, mask)) {
		smp_inval_intr();
		cpu_pause();
#ifdef LOOPRECOVER
		if (tsc_frequency && rdtsc() - tsc_base > tsc_frequency) {
			/*
			 * cpuid 	- cpu doing the waiting
			 * invltlb_mask - IPI in progress
			 */
			kprintf("smp_invltlb %2d: WARNING blocked %d sec: "
				"inv=%08jx "
				"smurf=%08jx "
#ifdef LOOPMASK_IN
				"in=%08jx "
#endif
				"idle=%08jx/%08jx\n",
				md->mi.gd_cpuid,
				repeats + 1,
				smp_invltlb_mask.ary[0],
				smp_smurf_mask.ary[0],
#ifdef LOOPMASK_IN
				smp_in_mask.ary[0],
#endif
				smp_idleinvl_mask.ary[0],
				smp_idleinvl_reqs.ary[0]);
			mdcpu->gd_xinvaltlb = 0;
			ATOMIC_CPUMASK_NANDMASK(smp_smurf_mask,
						smp_invltlb_mask);
			smp_invlpg(&smp_active_mask);

			/*
			 * Reload tsc_base for retry, give up after
			 * 10 seconds (60 seconds if in VM).
			 */
			tsc_base = rdtsc();
			if (++repeats > invlpg_timeout) {
				kprintf("smp_invltlb: giving up\n");
				CPUMASK_ASSZERO(smp_invltlb_mask);
			}
		}
#endif
	}
	write_rflags(rflags);
	crit_exit_gd(&md->mi);
}

/*
 * Called from a critical section with interrupts hard-disabled.
 * This function issues an XINVLTLB IPI and then executes any pending
 * command on the current cpu before returning.
 */
void
smp_invlpg(cpumask_t *cmdmask)
{
	struct mdglobaldata *md = mdcpu;
	cpumask_t mask;

	if (report_invlpg_src > 0) {
		if (--report_invlpg_src <= 0)
			print_backtrace(8);
	}

	/*
	 * Disallow normal interrupts, set all active cpus in the pmap,
	 * plus our own for completion processing (it might or might not
	 * be part of the set).
	 */
	mask = smp_active_mask;
	CPUMASK_ANDMASK(mask, *cmdmask);
	CPUMASK_ORMASK(mask, md->mi.gd_cpumask);

	/*
	 * Avoid double-queuing IPIs, which can deadlock us.  We must disable
	 * real interrupts when setting the smurf flags or we might race a
	 * XINVLTLB before we manage to send the ipi's for the bits we set.
	 *
	 * NOTE: We might be including our own cpu in the smurf mask.
	 */
	smp_smurf_fetchset(&mask);

	/*
	 * Issue the IPI.  Note that the XINVLTLB IPI runs regardless of
	 * the critical section count on the target cpus.
	 *
	 * We do not include our own cpu when issuing the IPI.
	 */
	if (all_but_self_ipi_enable &&
	    (all_but_self_ipi_enable >= 2 ||
	     CPUMASK_CMPMASKEQ(smp_startup_mask, mask))) {
		all_but_self_ipi(XINVLTLB_OFFSET);
	} else {
		CPUMASK_NANDMASK(mask, md->mi.gd_cpumask);
		selected_apic_ipi(mask, XINVLTLB_OFFSET, APIC_DELMODE_FIXED);
	}

	/*
	 * This will synchronously wait for our command to complete,
	 * as well as process commands from other cpus.  It also handles
	 * reentrancy.
	 *
	 * (interrupts are disabled and we are in a critical section here)
	 */
	smp_inval_intr();
}

/*
 * Issue rip/rsp sniffs
 */
void
smp_sniff(void)
{
	globaldata_t gd = mycpu;
	int dummy;
	register_t rflags;

	/*
	 * Ignore all_but_self_ipi_enable here and just use it.
	 */
	rflags = read_rflags();
	cpu_disable_intr();
	all_but_self_ipi(XSNIFF_OFFSET);
	gd->gd_sample_pc = smp_sniff;
	gd->gd_sample_sp = &dummy;
	write_rflags(rflags);
}

void
cpu_sniff(int dcpu)
{
	globaldata_t rgd = globaldata_find(dcpu);
	register_t rflags;
	int dummy;

	/*
	 * Ignore all_but_self_ipi_enable here and just use it.
	 */
	rflags = read_rflags();
	cpu_disable_intr();
	single_apic_ipi(dcpu, XSNIFF_OFFSET, APIC_DELMODE_FIXED);
	rgd->gd_sample_pc = cpu_sniff;
	rgd->gd_sample_sp = &dummy;
	write_rflags(rflags);
}

/*
 * Called from Xinvltlb assembly with interrupts hard-disabled and in a
 * critical section.  gd_intr_nesting_level may or may not be bumped
 * depending on entry.
 *
 * THIS CODE IS INTENDED TO EXPLICITLY IGNORE THE CRITICAL SECTION COUNT.
 * THAT IS, THE INTERRUPT IS INTENDED TO FUNCTION EVEN WHEN MAINLINE CODE
 * IS IN A CRITICAL SECTION.
 */
void
smp_inval_intr(void)
{
	struct mdglobaldata *md = mdcpu;
	cpumask_t cpumask;
#ifdef LOOPRECOVER
	tsc_uclock_t tsc_base = rdtsc();
#endif

#if 0
	/*
	 * The idle code is in a critical section, but that doesn't stop
	 * Xinvltlb from executing, so deal with the race which can occur
	 * in that situation.  Otherwise r-m-w operations by pmap_inval_intr()
	 * may have problems.
	 */
	if (ATOMIC_CPUMASK_TESTANDCLR(smp_idleinvl_reqs, md->mi.gd_cpuid)) {
		ATOMIC_CPUMASK_NANDBIT(smp_invltlb_mask, md->mi.gd_cpuid);
		cpu_invltlb();
		cpu_mfence();
	}
#endif

	/*
	 * This is a real mess.  I'd like to just leave interrupts disabled
	 * but it can cause the lapic to deadlock if too many interrupts queue
	 * to it, due to the idiotic design of the lapic.  So instead we have
	 * to enter a critical section so normal interrupts are made pending
	 * and track whether this one was reentered.
	 */
	if (md->gd_xinvaltlb) {		/* reentrant on cpu */
		md->gd_xinvaltlb = 2;
		return;
	}
	md->gd_xinvaltlb = 1;

	/*
	 * Check only those cpus with active Xinvl* commands pending.
	 *
	 * We are going to enable interrupts so make sure we are in a
	 * critical section.  This is necessary to avoid deadlocking
	 * the lapic and to ensure that we execute our commands prior to
	 * any nominal interrupt or preemption.
	 *
	 * WARNING! It is very important that we only clear out but in
	 *	    smp_smurf_mask once for each interrupt we take.  In
	 *	    this case, we clear it on initial entry and only loop
	 *	    on the reentrancy detect (caused by another interrupt).
	 */
	cpumask = smp_invmask;
#ifdef LOOPMASK_IN
	ATOMIC_CPUMASK_ORBIT(smp_in_mask, md->mi.gd_cpuid);
#endif
loop:
	cpu_enable_intr();
	ATOMIC_CPUMASK_NANDBIT(smp_smurf_mask, md->mi.gd_cpuid);

	/*
	 * Specific page request(s), and we can't return until all bits
	 * are zero.
	 */
	for (;;) {
		int toolong;

		/*
		 * Also execute any pending full invalidation request in
		 * this loop.
		 */
		if (CPUMASK_TESTBIT(smp_invltlb_mask, md->mi.gd_cpuid)) {
			ATOMIC_CPUMASK_NANDBIT(smp_invltlb_mask,
					       md->mi.gd_cpuid);
			cpu_invltlb();
			cpu_mfence();
		}

#ifdef LOOPRECOVER
		if (tsc_frequency && rdtsc() - tsc_base > tsc_frequency) {
			/*
			 * cpuid 	- cpu doing the waiting
			 * invmask	- IPI in progress
			 * invltlb_mask - which ones are TLB invalidations?
			 */
			kprintf("smp_inval_intr %2d, WARNING blocked >1 sec "
				"inv=%08jx tlbm=%08jx "
				"smurf=%08jx "
#ifdef LOOPMASK_IN
				"in=%08jx "
#endif
				"idle=%08jx/%08jx\n",
				md->mi.gd_cpuid,
				smp_invmask.ary[0],
				smp_invltlb_mask.ary[0],
				smp_smurf_mask.ary[0],
#ifdef LOOPMASK_IN
				smp_in_mask.ary[0],
#endif
				smp_idleinvl_mask.ary[0],
				smp_idleinvl_reqs.ary[0]);
			tsc_base = rdtsc();
			toolong = 1;
		} else {
			toolong = 0;
		}
#else
		toolong = 0;
#endif

		/*
		 * We can only add bits to the cpumask to test during the
		 * loop because the smp_invmask bit is cleared once the
		 * originator completes the command (the targets may still
		 * be cycling their own completions in this loop, afterwords).
		 *
		 * lfence required prior to all tests as this Xinvltlb
		 * interrupt could race the originator (already be in progress
		 * wnen the originator decides to issue, due to an issue by
		 * another cpu).
		 */
		cpu_lfence();
		CPUMASK_ORMASK(cpumask, smp_invmask);
		/*cpumask = smp_active_mask;*/	/* XXX */
		cpu_lfence();

		if (pmap_inval_intr(&cpumask, toolong) == 0) {
			/*
			 * Clear our smurf mask to allow new IPIs, but deal
			 * with potential races.
			 */
			break;
		}

		/*
		 * Test if someone sent us another invalidation IPI, break
		 * out so we can take it to avoid deadlocking the lapic
		 * interrupt queue (? stupid intel, amd).
		 */
		if (md->gd_xinvaltlb == 2)
			break;
		/*
		if (CPUMASK_TESTBIT(smp_smurf_mask, md->mi.gd_cpuid))
			break;
		*/
	}

	/*
	 * Full invalidation request
	 */
	if (CPUMASK_TESTBIT(smp_invltlb_mask, md->mi.gd_cpuid)) {
		ATOMIC_CPUMASK_NANDBIT(smp_invltlb_mask,
				       md->mi.gd_cpuid);
		cpu_invltlb();
		cpu_mfence();
	}

	/*
	 * Check to see if another Xinvltlb interrupt occurred and loop up
	 * if it did.
	 */
	cpu_disable_intr();
	if (md->gd_xinvaltlb == 2) {
		md->gd_xinvaltlb = 1;
		goto loop;
	}
#ifdef LOOPMASK_IN
	ATOMIC_CPUMASK_NANDBIT(smp_in_mask, md->mi.gd_cpuid);
#endif
	md->gd_xinvaltlb = 0;
}

void
cpu_wbinvd_on_all_cpus_callback(void *arg)
{
	wbinvd();
}

/*
 * When called the executing CPU will send an IPI to all other CPUs
 * requesting that they halt execution.
 *
 * Usually (but not necessarily) called with 'other_cpus' as its arg.
 *
 *  - Signals all CPUs in map to stop.
 *  - Waits for each to stop.
 *
 * Returns:
 *  -1: error
 *   0: NA
 *   1: ok
 *
 * XXX FIXME: this is not MP-safe, needs a lock to prevent multiple CPUs
 *            from executing at same time.
 */
int
stop_cpus(cpumask_t map)
{
	cpumask_t mask;

	CPUMASK_ANDMASK(map, smp_active_mask);

	/* send the Xcpustop IPI to all CPUs in map */
	selected_apic_ipi(map, XCPUSTOP_OFFSET, APIC_DELMODE_FIXED);

	do {
		mask = stopped_cpus;
		CPUMASK_ANDMASK(mask, map);
		/* spin */
	} while (CPUMASK_CMPMASKNEQ(mask, map));

	return 1;
}


/*
 * Called by a CPU to restart stopped CPUs. 
 *
 * Usually (but not necessarily) called with 'stopped_cpus' as its arg.
 *
 *  - Signals all CPUs in map to restart.
 *  - Waits for each to restart.
 *
 * Returns:
 *  -1: error
 *   0: NA
 *   1: ok
 */
int
restart_cpus(cpumask_t map)
{
	cpumask_t mask;

	/* signal other cpus to restart */
	mask = map;
	CPUMASK_ANDMASK(mask, smp_active_mask);
	cpu_ccfence();
	started_cpus = mask;
	cpu_ccfence();

	/* wait for each to clear its bit */
	while (CPUMASK_CMPMASKNEQ(stopped_cpus, map))
		cpu_pause();

	return 1;
}

/*
 * This is called once the mpboot code has gotten us properly relocated
 * and the MMU turned on, etc.   ap_init() is actually the idle thread,
 * and when it returns the scheduler will call the real cpu_idle() main
 * loop for the idlethread.  Interrupts are disabled on entry and should
 * remain disabled at return.
 */
void
ap_init(void)
{
	int	cpu_id;

	/*
	 * Adjust smp_startup_mask to signal the BSP that we have started
	 * up successfully.  Note that we do not yet hold the BGL.  The BSP
	 * is waiting for our signal.
	 *
	 * We can't set our bit in smp_active_mask yet because we are holding
	 * interrupts physically disabled and remote cpus could deadlock
	 * trying to send us an IPI.
	 */
	ATOMIC_CPUMASK_ORBIT(smp_startup_mask, mycpu->gd_cpuid);
	cpu_mfence();

	/*
	 * Interlock for LAPIC initialization.  Wait until mp_finish_lapic is
	 * non-zero, then get the MP lock.
	 *
	 * Note: We are in a critical section.
	 *
	 * Note: we are the idle thread, we can only spin.
	 *
	 * Note: The load fence is memory volatile and prevents the compiler
	 * from improperly caching mp_finish_lapic, and the cpu from improperly
	 * caching it.
	 */
	while (mp_finish_lapic == 0) {
		cpu_pause();
		cpu_lfence();
	}
#if 0
	while (try_mplock() == 0) {
		cpu_pause();
		cpu_lfence();
	}
#endif

	if (cpu_feature & CPUID_TSC) {
		/*
		 * The BSP is constantly updating tsc0_offset, figure out
		 * the relative difference to synchronize ktrdump.
		 */
		tsc_offsets[mycpu->gd_cpuid] = rdtsc() - tsc0_offset;
	}

	/* BSP may have changed PTD while we're waiting for the lock */
	cpu_invltlb();

	/* Build our map of 'other' CPUs. */
	mycpu->gd_other_cpus = smp_startup_mask;
	ATOMIC_CPUMASK_NANDBIT(mycpu->gd_other_cpus, mycpu->gd_cpuid);

	/* A quick check from sanity claus */
	cpu_id = APICID_TO_CPUID(LAPIC_READID);
	if (mycpu->gd_cpuid != cpu_id) {
		kprintf("SMP: assigned cpuid = %d\n", mycpu->gd_cpuid);
		kprintf("SMP: actual cpuid = %d lapicid %d\n",
			cpu_id, LAPIC_READID);
#if 0 /* JGXXX */
		kprintf("PTD[MPPTDI] = %p\n", (void *)PTD[MPPTDI]);
#endif
		panic("cpuid mismatch! boom!!");
	}

	/* Initialize AP's local APIC for irq's */
	lapic_init(FALSE);

	/* LAPIC initialization is done */
	ATOMIC_CPUMASK_ORBIT(smp_lapic_mask, mycpu->gd_cpuid);
	cpu_mfence();

#if 0
	/* Let BSP move onto the next initialization stage */
	rel_mplock();
#endif

	/*
	 * Interlock for finalization.  Wait until mp_finish is non-zero,
	 * then get the MP lock.
	 *
	 * Note: We are in a critical section.
	 *
	 * Note: we are the idle thread, we can only spin.
	 *
	 * Note: The load fence is memory volatile and prevents the compiler
	 * from improperly caching mp_finish, and the cpu from improperly
	 * caching it.
	 */
	while (mp_finish == 0) {
		cpu_pause();
		cpu_lfence();
	}

	/* BSP may have changed PTD while we're waiting for the lock */
	cpu_invltlb();

	/* Set memory range attributes for this CPU to match the BSP */
	mem_range_AP_init();

	/*
	 * Once we go active we must process any IPIQ messages that may
	 * have been queued, because no actual IPI will occur until we
	 * set our bit in the smp_active_mask.  If we don't the IPI
	 * message interlock could be left set which would also prevent
	 * further IPIs.
	 *
	 * The idle loop doesn't expect the BGL to be held and while
	 * lwkt_switch() normally cleans things up this is a special case
	 * because we returning almost directly into the idle loop.
	 *
	 * The idle thread is never placed on the runq, make sure
	 * nothing we've done put it there.
	 */

	/*
	 * Hold a critical section and allow real interrupts to occur.  Zero
	 * any spurious interrupts which have accumulated, then set our
	 * smp_active_mask indicating that we are fully operational.
	 */
	crit_enter();
	__asm __volatile("sti; pause; pause"::);
	bzero(mdcpu->gd_ipending, sizeof(mdcpu->gd_ipending));
	ATOMIC_CPUMASK_ORBIT(smp_active_mask, mycpu->gd_cpuid);

	/*
	 * Wait until all cpus have set their smp_active_mask and have fully
	 * operational interrupts before proceeding.
	 *
	 * We need a final cpu_invltlb() because we would not have received
	 * any until we set our bit in smp_active_mask.
	 */
	while (mp_finish == 1) {
		cpu_pause();
		cpu_lfence();
	}
	cpu_invltlb();

	/*
	 * Initialize per-cpu clocks and do other per-cpu initialization.
	 * At this point code is expected to be able to use the full kernel
	 * API.
	 */
	initclocks_pcpu();	/* clock interrupts (via IPIs) */

	/*
	 * Since we may have cleaned up the interrupt triggers, manually
	 * process any pending IPIs before exiting our critical section.
	 * Once the critical section has exited, normal interrupt processing
	 * may occur.
	 */
	atomic_swap_int(&mycpu->gd_npoll, 0);
	lwkt_process_ipiq();
	crit_exit();

	/*
	 * Final final, allow the waiting BSP to resume the boot process,
	 * return 'into' the idle thread bootstrap.
	 */
	ATOMIC_CPUMASK_ORBIT(smp_finalize_mask, mycpu->gd_cpuid);
	KKASSERT((curthread->td_flags & TDF_RUNQ) == 0);
}

/*
 * Get SMP fully working before we start initializing devices.
 */
static
void
ap_finish(void)
{
	if (bootverbose)
		kprintf("Finish MP startup\n");
	rel_mplock();

	/*
	 * Wait for the active mask to complete, after which all cpus will
	 * be accepting interrupts.
	 */
	mp_finish = 1;
	while (CPUMASK_CMPMASKNEQ(smp_active_mask, smp_startup_mask)) {
		cpu_pause();
		cpu_lfence();
	}

	/*
	 * Wait for the finalization mask to complete, after which all cpus
	 * have completely finished initializing and are entering or are in
	 * their idle thread.
	 *
	 * BSP should have received all required invltlbs but do another
	 * one just in case.
	 */
	cpu_invltlb();
	mp_finish = 2;
	while (CPUMASK_CMPMASKNEQ(smp_finalize_mask, smp_startup_mask)) {
		cpu_pause();
		cpu_lfence();
	}

	while (try_mplock() == 0) {
		cpu_pause();
		cpu_lfence();
	}

	if (bootverbose) {
		kprintf("Active CPU Mask: %016jx\n",
			(uintmax_t)CPUMASK_LOWMASK(smp_active_mask));
	}
}

SYSINIT(finishsmp, SI_BOOT2_FINISH_SMP, SI_ORDER_FIRST, ap_finish, NULL);

/*
 * Interrupts must be hard-disabled by caller
 */
void
cpu_send_ipiq(int dcpu)
{
	if (CPUMASK_TESTBIT(smp_active_mask, dcpu))
                single_apic_ipi(dcpu, XIPIQ_OFFSET, APIC_DELMODE_FIXED);
}

#if 0	/* single_apic_ipi_passive() not working yet */
/*
 * Returns 0 on failure, 1 on success
 */
int
cpu_send_ipiq_passive(int dcpu)
{
        int r = 0;
	if (CPUMASK_TESTBIT(smp_active_mask, dcpu)) {
                r = single_apic_ipi_passive(dcpu, XIPIQ_OFFSET,
                                        APIC_DELMODE_FIXED);
        }
	return(r);
}
#endif

static void
mp_bsp_simple_setup(void)
{
	struct mdglobaldata *gd;
	size_t ipiq_size;

	/* build our map of 'other' CPUs */
	mycpu->gd_other_cpus = smp_startup_mask;
	CPUMASK_NANDBIT(mycpu->gd_other_cpus, mycpu->gd_cpuid);

	gd = (struct mdglobaldata *)mycpu;
	gd->gd_acpi_id = CPUID_TO_ACPIID(mycpu->gd_cpuid);

	ipiq_size = sizeof(struct lwkt_ipiq) * ncpus;
	mycpu->gd_ipiq = (void *)kmem_alloc(kernel_map, ipiq_size,
					    VM_SUBSYS_IPIQ);
	bzero(mycpu->gd_ipiq, ipiq_size);

	/* initialize arc4random. */
	arc4_init_pcpu(0);

	pmap_set_opt();

	if (cpu_feature & CPUID_TSC)
		tsc0_offset = rdtsc();
}


/*
 * CPU TOPOLOGY DETECTION FUNCTIONS
 */

/* Detect intel topology using CPUID 
 * Ref: http://www.intel.com/Assets/PDF/appnote/241618.pdf, pg 41
 */
static void
detect_intel_topology(int count_htt_cores)
{
	int shift = 0;
	int ecx_index = 0;
	int core_plus_logical_bits = 0;
	int cores_per_package;
	int logical_per_package;
	int logical_per_core;
	unsigned int p[4];

	if (cpu_high >= 0xb) {
		goto FUNC_B;

	} else if (cpu_high >= 0x4) {
		goto FUNC_4;

	} else {
		core_bits = 0;
		for (shift = 0; (1 << shift) < count_htt_cores; ++shift)
			;
		logical_CPU_bits = 1 << shift;
		return;
	}

FUNC_B:
	cpuid_count(0xb, FUNC_B_THREAD_LEVEL, p);

	/* if 0xb not supported - fallback to 0x4 */
	if (p[1] == 0 || (FUNC_B_TYPE(p[2]) != FUNC_B_THREAD_TYPE)) {
		goto FUNC_4;
	}

	logical_CPU_bits = FUNC_B_BITS_SHIFT_NEXT_LEVEL(p[0]);

	ecx_index = FUNC_B_THREAD_LEVEL + 1;
	do {
		cpuid_count(0xb, ecx_index, p);

		/* Check for the Core type in the implemented sub leaves. */
		if (FUNC_B_TYPE(p[2]) == FUNC_B_CORE_TYPE) {
			core_plus_logical_bits = FUNC_B_BITS_SHIFT_NEXT_LEVEL(p[0]);
			break;
		}

		ecx_index++;

	} while (FUNC_B_TYPE(p[2]) != FUNC_B_INVALID_TYPE);

	core_bits = core_plus_logical_bits - logical_CPU_bits;

	return;

FUNC_4:
	cpuid_count(0x4, 0, p);
	cores_per_package = FUNC_4_MAX_CORE_NO(p[0]) + 1;

	logical_per_package = count_htt_cores;
	logical_per_core = logical_per_package / cores_per_package;
	
	for (shift = 0; (1 << shift) < logical_per_core; ++shift)
		;
	logical_CPU_bits = shift;

	for (shift = 0; (1 << shift) < cores_per_package; ++shift)
		;
	core_bits = shift;

	return;
}

/* Detect AMD topology using CPUID
 * Ref: http://support.amd.com/us/Embedded_TechDocs/25481.pdf, last page
 */
static void
detect_amd_topology(int count_htt_cores)
{
	int shift = 0;
	if ((cpu_feature & CPUID_HTT) && (amd_feature2 & AMDID2_CMP)) {
		if (cpu_procinfo2 & AMDID_COREID_SIZE) {
			core_bits = (cpu_procinfo2 & AMDID_COREID_SIZE) >>
				    AMDID_COREID_SIZE_SHIFT;
		} else {
			core_bits = (cpu_procinfo2 & AMDID_CMP_CORES) + 1;
			for (shift = 0; (1 << shift) < core_bits; ++shift)
				;
			core_bits = shift;
		}
		logical_CPU_bits = count_htt_cores >> core_bits;
		for (shift = 0; (1 << shift) < logical_CPU_bits; ++shift)
			;
		logical_CPU_bits = shift;

		kprintf("core_bits %d logical_CPU_bits %d\n",
			core_bits - logical_CPU_bits, logical_CPU_bits);

		if (amd_feature2 & AMDID2_TOPOEXT) {
			u_int p[4];	/* eax,ebx,ecx,edx */
			int nodes;

			cpuid_count(0x8000001e, 0, p);

			switch(((p[1] >> 8) & 3) + 1) {
			case 1:
				logical_CPU_bits = 0;
				break;
			case 2:
				logical_CPU_bits = 1;
				break;
			case 3:
			case 4:
				logical_CPU_bits = 2;
				break;
			}

			/*
			 * Nodes are kind of a stand-in for packages*sockets,
			 * but can be thought of in terms of Numa domains.
			 */
			nodes = ((p[2] >> 8) & 7) + 1;
			switch(nodes) {
			case 8:
			case 7:
			case 6:
			case 5:
				--core_bits;
				/* fallthrough */
			case 4:
			case 3:
				--core_bits;
				/* fallthrough */
			case 2:
				--core_bits;
				/* fallthrough */
			case 1:
				break;
			}
			core_bits -= logical_CPU_bits;
			kprintf("%d-way htt, %d Nodes, %d cores/node\n",
				(int)(((p[1] >> 8) & 3) + 1),
				nodes,
				1 << core_bits);

		}
#if 0
		if (amd_feature2 & AMDID2_TOPOEXT) {
			u_int p[4];
			int i;
			int type;
			int level;
			int share_count;

			logical_CPU_bits = 0;
			core_bits = 0;

			for (i = 0; i < 256; ++i)  {
				cpuid_count(0x8000001d, i, p);
				type = p[0] & 0x1f;
				level = (p[0] >> 5) & 0x7;
				share_count = 1 + ((p[0] >> 14) & 0xfff);

				if (type == 0)
					break;
				kprintf("Topology probe i=%2d type=%d "
					"level=%d share_count=%d\n",
					i, type, level, share_count);
				shift = 0;
				while ((1 << shift) < share_count)
					++shift;

				switch(type) {
				case 1:
					/*
					 * CPUID_TYPE_SMT
					 *
					 * Logical CPU (SMT)
					 */
					logical_CPU_bits = shift;
					break;
				case 2:
					/*
					 * CPUID_TYPE_CORE
					 *
					 * Physical subdivision of a package
					 */
					core_bits = logical_CPU_bits +
						    shift;
					break;
				case 3:
					/*
					 * CPUID_TYPE_CACHE
					 *
					 * CPU L1/L2/L3 cache
					 */
					break;
				case 4:
					/*
					 * CPUID_TYPE_PKG
					 *
					 * Package aka chip, equivalent to
					 * socket
					 */
					break;
				}
			}
		}
#endif
	} else {
		for (shift = 0; (1 << shift) < count_htt_cores; ++shift)
			;
		core_bits = shift;
		logical_CPU_bits = 0;
	}
}

static void
amd_get_compute_unit_id(void *arg)
{
	u_int regs[4];

	do_cpuid(0x8000001e, regs);
	cpu_node_t * mynode = get_cpu_node_by_cpuid(mycpuid);

	/* 
	 * AMD - CPUID Specification September 2010
	 * page 34 - //ComputeUnitID = ebx[0:7]//
	 */
	mynode->compute_unit_id = regs[1] & 0xff;
}

int
fix_amd_topology(void)
{
	cpumask_t mask;

	if (cpu_vendor_id != CPU_VENDOR_AMD)
		return -1;
	if ((amd_feature2 & AMDID2_TOPOEXT) == 0)
		return -1;

	CPUMASK_ASSALLONES(mask);
	lwkt_cpusync_simple(mask, amd_get_compute_unit_id, NULL);

	kprintf("Compute unit iDS:\n");
	int i;
	for (i = 0; i < ncpus; i++) {
		kprintf("%d-%d; \n",
			i, get_cpu_node_by_cpuid(i)->compute_unit_id);
	}
	return 0;
}

/*
 * Calculate
 * - logical_CPU_bits
 * - core_bits
 * With the values above (for AMD or INTEL) we are able to generally
 * detect the CPU topology (number of cores for each level):
 * Ref: http://wiki.osdev.org/Detecting_CPU_Topology_(80x86)
 * Ref: http://www.multicoreinfo.com/research/papers/whitepapers/Intel-detect-topology.pdf
 */
void
detect_cpu_topology(void)
{
	static int topology_detected = 0;
	int count = 0;
	
	if (topology_detected)
		goto OUT;
	if ((cpu_feature & CPUID_HTT) == 0) {
		core_bits = 0;
		logical_CPU_bits = 0;
		goto OUT;
	}
	count = (cpu_procinfo & CPUID_HTT_CORES) >> CPUID_HTT_CORE_SHIFT;

	if (cpu_vendor_id == CPU_VENDOR_INTEL)
		detect_intel_topology(count);	
	else if (cpu_vendor_id == CPU_VENDOR_AMD)
		detect_amd_topology(count);
	topology_detected = 1;

OUT:
	if (bootverbose) {
		kprintf("Bits within APICID: logical_CPU_bits: %d; "
			"core_bits: %d\n",
			logical_CPU_bits, core_bits);
	}
}

/*
 * Interface functions to calculate chip_ID,
 * core_number and logical_number
 * Ref: http://wiki.osdev.org/Detecting_CPU_Topology_(80x86)
 */
int
get_chip_ID(int cpuid)
{
	return get_apicid_from_cpuid(cpuid) >>
	    (logical_CPU_bits + core_bits);
}

int
get_chip_ID_from_APICID(int apicid)
{
	return apicid >> (logical_CPU_bits + core_bits);
}

int
get_core_number_within_chip(int cpuid)
{
	return ((get_apicid_from_cpuid(cpuid) >> logical_CPU_bits) &
		((1 << core_bits) - 1));
}

int
get_logical_CPU_number_within_core(int cpuid)
{
	return (get_apicid_from_cpuid(cpuid) &
		((1 << logical_CPU_bits) - 1));
}
