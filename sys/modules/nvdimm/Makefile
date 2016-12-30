# nvdimm Loadable Kernel Module
#
# $FreeBSD$

.PATH:  ${.CURDIR}/../../dev/nvdimm

KMOD=	nvdimm
SRCS=	nvdimm.c nvdimm_copy.S
SRCS+=	device_if.h bus_if.h ntb_if.h

CFLAGS += -I${.CURDIR}/../../dev/ntb

.include <bsd.kmod.mk>
