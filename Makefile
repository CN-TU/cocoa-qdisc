KERNEL_VERSION := $(shell uname -r)
IDIR := /lib/modules/$(KERNEL_VERSION)/kernel/net/sched/
KDIR := /lib/modules/$(KERNEL_VERSION)/build
PWD := $(shell pwd)
# $(info KBUILD_CFLAGS is $(KBUILD_CFLAGS))
ccflags-y := -msse2

default:
	@$(MAKE) -C $(KDIR) M=$(PWD) modules

install:
	install -v -m 644 sch_cocoa.ko $(IDIR)
	depmod "$(KERNEL_VERSION)"
	[ "$(KERNEL_VERSION)" != `uname -r` ] || modprobe sch_cocoa

clean:
	@$(MAKE) -C $(KDIR) M=$(PWD) clean

obj-m := sch_cocoa.o
