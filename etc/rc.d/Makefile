# $NetBSD: Makefile,v 1.16 2001/01/14 15:37:22 minoura Exp $
# $FreeBSD: src/etc/rc.d/Makefile,v 1.20 2003/06/29 05:15:57 mtm Exp $

.include <bsd.own.mk>

# note: bgfsk and lomac left out (from 5.0)
#
FILES=	DAEMON FILESYSTEMS LOGIN NETWORKING SERVERS \
	accounting addswap adjkerntz automount automountd autounmountd \
	bootconf bootparams btconfig bthcid ccd cleanvar cryptdisks \
	cleartmp cron cryptdisks \
	devd devfs dhclient dhcp_client dhcpcd diskless dmesg dntpd dumpon \
	fixbootfile fsck ftpd hostname hotplugd \
	inetd initdiskless initrandom ip6addrctl ip6fw ipfw ipfw3 \
	jail keyserv \
	ldconfig local localdaemons lockd lpd lvm \
	mixer modules motd mountcritlocal mountcritremote mountd mounttmpfs \
	moused msgs \
	named netif netoptions newsyslog \
	network_ipv6 nfsclient nfsd nfsserver nisdomain nscd nsswitch \
	othermta pf pflog powerd ppp pppoed pwcheck \
	quota random rarpd rcconf resident rndcontrol root route6d routed \
	routing rpcbind rtadvd rtsold rwho sysdb savecore sdpd securelevel \
	sendmail sensorsd serial sppp sshd statd swap1 syscons \
	sysctl syslogd sysvipcd \
	ttys udevd udevd_early \
	varsym vfs_quota vinum virecover vkernel vknetd \
	watchdogd wg wpa_supplicant \
	ypbind yppasswdd ypserv ypset ypupdated ypxfrd

FILESDIR=	/etc/rc.d
FILESMODE=	${BINMODE}

NOOBJ=

.include <bsd.prog.mk>
