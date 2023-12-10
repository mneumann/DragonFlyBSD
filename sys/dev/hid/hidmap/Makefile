.PATH: ${.CURDIR}/..

KMOD	= hidmap
SRCS	= \
	hidmap.c \
	opt_hid.h \
	bus_if.h device_if.h

EXPORT_SYMS=	YES

.include <bsd.kmod.mk>
