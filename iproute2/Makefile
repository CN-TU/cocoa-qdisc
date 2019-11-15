# SPDX-License-Identifier: GPL-2.0
# Top level Makefile for iproute2

ifeq ("$(origin V)", "command line")
VERBOSE = $(V)
endif
ifndef VERBOSE
VERBOSE = 0
endif

ifeq ($(VERBOSE),0)
MAKEFLAGS += --no-print-directory
endif

PREFIX?=/usr
LIBDIR?=$(PREFIX)/lib
CONFDIR?=/etc/iproute2
DATADIR?=$(PREFIX)/share
HDRDIR?=$(PREFIX)/include/iproute2
KERNEL_INCLUDE?=/usr/include
BASH_COMPDIR?=$(DATADIR)/bash-completion/completions

# Path to db_185.h include
DBM_INCLUDE:=$(DESTDIR)/usr/include

SHARED_LIBS = y

DEFINES= -DRESOLVE_HOSTNAMES -DLIBDIR=\"$(LIBDIR)\"
ifneq ($(SHARED_LIBS),y)
DEFINES+= -DNO_SHARED_LIBS
endif

DEFINES+=-DCONFDIR=\"$(CONFDIR)\" \

CC := gcc
HOSTCC ?= $(CC)
DEFINES += -D_GNU_SOURCE
# Turn on transparent support for LFS
DEFINES += -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE
CCOPTS = -O2
WFLAGS := -Wall -Wstrict-prototypes  -Wmissing-prototypes
WFLAGS += -Wmissing-declarations -Wold-style-definition -Wformat=2

CFLAGS := $(WFLAGS) $(CCOPTS) -I../include -I../include/uapi $(DEFINES) $(CFLAGS)
YACCFLAGS = -d -t -v

SUBDIRS=tc

all: config.mk
	@set -e; \
	for i in $(SUBDIRS); \
	do echo; echo $$i; $(MAKE) $(MFLAGS) -C $$i; done

help:
	@echo "Make Targets:"
	@echo " all                 - build binaries"
	@echo " clean               - remove products of build"
	@echo " distclean           - remove configuration and build"
	@echo " install             - install binaries on local machine"
	@echo ""
	@echo "Make Arguments:"
	@echo " V=[0|1]             - set build verbosity level"

config.mk:
	sh configure $(KERNEL_INCLUDE)

install: all
	@for i in $(SUBDIRS);  do $(MAKE) -C $$i install; done

clean:
	@for i in $(SUBDIRS); \
	do $(MAKE) $(MFLAGS) -C $$i clean; done

clobber:
	touch config.mk
	$(MAKE) $(MFLAGS) clean
	rm -f config.mk cscope.*

distclean: clobber

cscope:
	cscope -b -q -R -Iinclude -stc

.EXPORT_ALL_VARIABLES:
