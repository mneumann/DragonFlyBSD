#	@(#)Makefile	8.2 (Berkeley) 1/4/94
# $FreeBSD: src/include/Makefile,v 1.109.2.27 2003/01/24 05:12:29 sam Exp $
#
# Doing a ``make install`` builds /usr/include
#
# The ``rm -rf''s used below are safe because rm doesn't follow symbolic
# links.

CLEANFILES= osreldate.h version vers.c vers.txt
SUBDIR= arpa protocols rpc rpcsvc xlocale
INCS=	a.out.h alloca.h ar.h assert.h bitstring.h byteswap.h \
	cpio.h ctype.h db.h dirent.h disktab.h \
	dlfcn.h elf.h elf-hints.h endian.h err.h \
	float.h fmtmsg.h fnmatch.h fstab.h fts.h ftw.h \
	getopt.h glob.h grp.h \
	iconv.h ieeefp.h ifaddrs.h iso646.h inttypes.h kenv.h \
	langinfo.h libgen.h limits.h link.h locale.h malloc_np.h \
	memory.h mntopts.h mpool.h mqueue.h monetary.h ndbm.h \
	netconfig.h netdb.h nl_types.h nlist.h nss.h nsswitch.h \
	objformat.h paths.h printf.h pthread.h pthread_np.h pwd.h \
	ranlib.h readpassphrase.h \
	re_comp.h resolv.h res_update.h runetype.h \
	search.h semaphore.h setjmp.h signal.h spawn.h \
	stdalign.h stdarg.h stdbool.h \
	stddef.h stdint.h stdio.h stdlib.h stdnoreturn.h \
	string.h stringlist.h strings.h sysexits.h \
	tar.h termios.h time.h timeconv.h ttyent.h \
	uchar.h unistd.h ulimit.h utime.h utmpx.h \
	uuid.h vis.h \
	wchar.h wctype.h wordexp.h xlocale.h

.if defined(WANT_HESIOD)
INCS+=	hesiod.h
.endif

# Only for default SHARED=copies case
SHDRS=	soundcard.h joystick.h

LHDRS=	aio.h errno.h fcntl.h linker_set.h poll.h sched.h syslog.h ucontext.h

# directories which also contain header files that need to be copied.
# Other directories, like 'bus' and 'netproto', are created using mtree.
#
# XXX allow these directories to not contain header files.
LDIRS=	net netbt netgraph netgraph7 netinet netinet6 sys vm

# Subdirectories containing header files to copy.  In symlink mode
# the subdirectory will be symlinked.
#
# NOTE: Care must be taken to adjust LSYMSUBDIRS below to remove
#       subdirectories whos parent directory is also listed.
#       If you make a mistake, part of your source tree might get
#       overwritten when buildworld is run.
#
LSUBDIRS= \
	bus/cam bus/cam/scsi \
	bus/isa bus/pccard bus/pci bus/ppbus bus/smbus bus/u4b \
	dev/disk/dm \
	dev/disk/mpt/mpilib \
	dev/misc/lpt dev/misc/ppi \
	dev/netif/wi \
	dev/raid/ciss dev/raid/mfi \
	dev/smbus/smb \
	dev/video/bktr dev/video/meteor \
	dev/virtual/nvmm dev/virtual/nvmm/x86 \
	libprop \
	net/altq net/bridge \
	net/dummynet net/dummynet3 \
	net/ip_mroute \
	net/ip6fw net/ipfw \
	net/ipfw3 net/ipfw3_basic net/ipfw3_layer2 net/ipfw3_layer4 \
	net/ipfw3_nat \
	net/lagg \
	net/pf \
	net/ppp_layer \
	net/sl net/sppp \
	net/tap net/tun \
	net/vlan \
	net/wg \
	netgraph/UI netgraph/async netgraph/bpf netgraph/bridge \
	netgraph/cisco netgraph/echo netgraph/eiface netgraph/etf \
	netgraph/ether netgraph/fec netgraph/frame_relay netgraph/hole \
	netgraph/iface netgraph/ksocket netgraph/l2tp netgraph/lmi \
	netgraph/mppc netgraph/one2many netgraph/ppp \
	netgraph/pppoe netgraph/pptpgre netgraph/rfc1490 netgraph/socket \
	netgraph/tee netgraph/tty netgraph/vjc \
	netgraph7/UI netgraph7/async netgraph7/bpf \
	netgraph7/bridge netgraph7/cisco netgraph7/deflate netgraph7/echo \
	netgraph7/eiface netgraph7/etf netgraph7/ether \
	netgraph7/frame_relay netgraph7/hole netgraph7/hub \
	netgraph7/iface netgraph7/ksocket netgraph7/l2tp netgraph7/lmi \
	netgraph7/mppc netgraph7/one2many netgraph7/ppp netgraph7/pppoe \
	netgraph7/pptpgre netgraph7/rfc1490 netgraph7/socket \
	netgraph7/tcpmss netgraph7/tee netgraph7/tty netgraph7/vjc \
	netproto/802_11 netproto/mpls netproto/smb \
	vfs/isofs/cd9660 \
	vfs/msdosfs vfs/nfs vfs/ntfs \
	vfs/smbfs vfs/udf vfs/ufs vfs/hammer vfs/hammer2 \
	vfs/autofs vfs/fuse vfs/tmpfs vfs/ext2fs

# For SHARED=symlinks, adjust LSYMSUBDIRS to remove subdirectories whos
# parent directory is also symlinked, avoiding the source tree being
# overwritten.  For example, 'bus/cam' is a symlink, so 'bus/cam/scsi'
# is also taken care of.
LSYMSUBDIRS:=	${LSUBDIRS:Nnet/*:Nnetgraph/*:Nnetgraph7/*}
LSYMSUBDIRS:=	${LSYMSUBDIRS:Nbus/cam/scsi}
LSYMSUBDIRS:=	${LSYMSUBDIRS:Ndev/virtual/nvmm/x86}

# Define SHARED to indicate whether you want symbolic links to the system
# source (``symlinks''), or a separate copy (``copies'').  ``symlinks'' is
# probably only useful for developers and should be avoided if you do not
# wish to tie your /usr/include and /usr/src together.
#SHARED=	symlinks
SHARED?=	copies

INCS+=	osreldate.h

osreldate.h:	${.CURDIR}/../sys/conf/newvers.sh \
		${.CURDIR}/../sys/sys/param.h
	@${ECHO} creating osreldate.h from newvers.sh
	setvar PARAMFILE ${.CURDIR}/../sys/sys/param.h; \
	. ${.CURDIR}/../sys/conf/newvers.sh "${.CURDIR}/.." ;	\
	echo "$$COPYRIGHT" > osreldate.h;			\
	echo "#ifdef _KERNEL" >> osreldate.h;			\
	echo '#error "osreldate.h must not be used in the kernel, use sys/param.h"' >> osreldate.h; \
	echo "#else" >> osreldate.h;				\
	echo "#undef __DragonFly_version" >> osreldate.h;	\
	echo "#define __DragonFly_version $$RELDATE" >> osreldate.h; \
	echo "#endif" >> osreldate.h

.for i in ${LHDRS}
INCSLINKS+=	sys/$i ${INCLUDEDIR}/$i
.endfor
.for i in ${MHDRS}
INCSLINKS+=	machine/$i ${INCLUDEDIR}/$i
.endfor
# For smbfs contrib.
INCSLINKS+=	netproto/smb ${INCLUDEDIR}/netsmb
# Some 3rd party software looks for <floatingpoint.h>
INCSLINKS+=	ieeefp.h ${INCLUDEDIR}/floatingpoint.h

# NOTE!
#
# machine/ header files come from the platform architecture and
# cpu/ header files come from the cpu architecture.  All code outside
# of the machine header files ALWAYS #include's <machine/blah.h>.  So
# if the platform architecture is missing a header file we have to
# copy it in from the cpu architecture.  This way we do not have to
# create dozens of pure forwarding headers for files that platform
# architecture does not need to enhance.

mtree_setup:
.for i in ${LDIRS} ${LSYMSUBDIRS} machine cpu crypto dev/acpica
	if [ -h ${DESTDIR}/usr/include/$i ]; then \
		rm -f ${DESTDIR}/usr/include/$i; \
	fi
.endfor
	mtree -deU -f ${.CURDIR}/../etc/mtree/BSD.include.dist \
		-p ${DESTDIR}/usr/include

copies:		mtree_setup
.for i in ${LDIRS} ${LSUBDIRS}
	cd ${.CURDIR}/../sys; \
		${INSTALL} -C -o ${BINOWN} -g ${BINGRP} -m 444 $i/*.h \
		${DESTDIR}/usr/include/$i
.endfor
	cd ${.CURDIR}/../sys; \
		${INSTALL} -C -o ${BINOWN} -g ${BINGRP} -m 444 crypto/rijndael/rijndael.h \
		${DESTDIR}/usr/include/crypto; \
		${INSTALL} -C -o ${BINOWN} -g ${BINGRP} -m 444 crypto/rmd160/rmd160.h \
		${DESTDIR}/usr/include/crypto; \
		${INSTALL} -C -o ${BINOWN} -g ${BINGRP} -m 444 opencrypto/*.h \
		${DESTDIR}/usr/include/crypto
	cd ${.CURDIR}/../sys/dev/acpica; \
		${INSTALL} -C -o ${BINOWN} -g ${BINGRP} -m 444 acpiio.h \
		${DESTDIR}/usr/include/dev/acpica
	cd ${.CURDIR}/../sys/dev/misc/evdev; \
		${INSTALL} -C -o ${BINOWN} -g ${BINGRP} -m 444 input.h \
		${DESTDIR}/usr/include/dev/misc/evdev
	cd ${.CURDIR}/../sys/dev/misc/evdev; \
		${INSTALL} -C -o ${BINOWN} -g ${BINGRP} -m 444 input-event-codes.h \
		${DESTDIR}/usr/include/dev/misc/evdev
	cd ${.CURDIR}/../sys/dev/misc/evdev; \
		${INSTALL} -C -o ${BINOWN} -g ${BINGRP} -m 444 input.h \
		${DESTDIR}/usr/include/compat/linux
	cd ${.CURDIR}/../sys/dev/misc/evdev; \
		${INSTALL} -C -o ${BINOWN} -g ${BINGRP} -m 444 input-event-codes.h \
		${DESTDIR}/usr/include/compat/linux
	cd ${.CURDIR}/../sys/dev/drm/include/linux; \
		${INSTALL} -C -o ${BINOWN} -g ${BINGRP} -m 444 compiler.h \
		${DESTDIR}/usr/include/compat/linux
	cd ${.CURDIR}/../sys/dev/drm/include/linux; \
		${INSTALL} -C -o ${BINOWN} -g ${BINGRP} -m 444 posix_types.h \
		${DESTDIR}/usr/include/compat/linux
	cd ${.CURDIR}/../sys/dev/drm/include/linux; \
		${INSTALL} -C -o ${BINOWN} -g ${BINGRP} -m 444 types.h \
		${DESTDIR}/usr/include/compat/linux
	cd ${.CURDIR}/../sys/dev/drm/include/uapi; \
		${INSTALL} -C -o ${BINOWN} -g ${BINGRP} -m 444 asm-generic/int-ll64.h \
		${DESTDIR}/usr/include/compat/uapi/asm-generic
	cd ${.CURDIR}/../sys/dev/drm/include/uapi; \
		${INSTALL} -C -o ${BINOWN} -g ${BINGRP} -m 444 linux/types.h \
		${DESTDIR}/usr/include/compat/uapi/linux
	cd ${.CURDIR}/../sys/dev/drm/include/asm; \
		${INSTALL} -C -o ${BINOWN} -g ${BINGRP} -m 444 bitsperlong.h \
		${DESTDIR}/usr/include/compat/asm
	cd ${.CURDIR}/../sys/dev/drm/include/asm; \
		${INSTALL} -C -o ${BINOWN} -g ${BINGRP} -m 444 int-ll64.h \
		${DESTDIR}/usr/include/compat/asm
	cd ${.CURDIR}/../sys/dev/drm/include/asm; \
		${INSTALL} -C -o ${BINOWN} -g ${BINGRP} -m 444 ioctl.h \
		${DESTDIR}/usr/include/compat/asm
.if exists(${.CURDIR}/../sys/cpu/${MACHINE_ARCH}/include)
	cd ${.CURDIR}/../sys/cpu/${MACHINE_ARCH}/include; \
		${INSTALL} -C -o ${BINOWN} -g ${BINGRP} -m 444 *.h \
		${DESTDIR}/usr/include/cpu
	# XXX this will cause quickworld to rebuild more junk
	# then it needs to.
	cpdup -o ${DESTDIR}/usr/include/cpu ${DESTDIR}/usr/include/machine
.endif
.if exists(${.CURDIR}/../sys/platform/${MACHINE_PLATFORM}/include)
	cd ${.CURDIR}/../sys/platform/${MACHINE_PLATFORM}/include; \
		${INSTALL} -C -o ${BINOWN} -g ${BINGRP} -m 444 *.h \
		${DESTDIR}/usr/include/machine
.if exists(${.CURDIR}/../sys/platform/${MACHINE_PLATFORM}/include/pc)
	cd ${.CURDIR}/../sys/platform/${MACHINE_PLATFORM}/include/pc; \
		${INSTALL} -C -o ${BINOWN} -g ${BINGRP} -m 444 *.h \
		${DESTDIR}/usr/include/machine/pc
.endif
.endif
.for i in ${SHDRS}
	${LN} -sf ../sys/$i ${DESTDIR}/usr/include/machine/$i
.endfor

symlinks:	mtree_setup
	@${ECHO} "Setting up symlinks to kernel source tree..."
.for i in ${LDIRS}
	rm -rf ${DESTDIR}/usr/include/$i
	${LN} -s ../../sys/$i ${DESTDIR}/usr/include/$i
.endfor
	rm -rf ${DESTDIR}/usr/include/crypto
	${LN} -s ../../sys/opencrypto ${DESTDIR}/usr/include/crypto
.for i in ${LSYMSUBDIRS}
	rm -rf ${DESTDIR}/usr/include/$i
	${LN} -s ${i:C;[^/]+/?;../;g}../sys/$i ${DESTDIR}/usr/include/$i
.endfor
	rm -rf ${DESTDIR}/usr/include/cpu
	${LN} -s ../../sys/cpu/${MACHINE_ARCH}/include ${DESTDIR}/usr/include/cpu
	rm -rf ${DESTDIR}/usr/include/machine
	cpdup ${.CURDIR}/../sys/cpu/${MACHINE_ARCH}/include \
		${DESTDIR}/usr/include/machine
	cpdup -o ${.CURDIR}/../sys/platform/${MACHINE_PLATFORM}/include \
		${DESTDIR}/usr/include/machine

.include <bsd.prog.mk>

installincludes: ${SHARED}
