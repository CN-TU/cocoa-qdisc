KERNEL_VERSION := $(shell uname -r)
IDIR := /lib/modules/$(KERNEL_VERSION)/kernel/net/sched/
KDIR := /lib/modules/$(KERNEL_VERSION)/build
PWD := $(shell pwd)
# $(info	KBUILD_CFLAGS is $(KBUILD_CFLAGS))
# KBUILD_CFLAGS := $(shell echo $(KBUILD_CFLAGS) | sed -e s/-mno-sse2//g )
# KBUILD_CFLAGS := $(shell echo $(KBUILD_CFLAGS) | sed -e s/-mno-sse//g )
# $(info	KBUILD_CFLAGS is $(KBUILD_CFLAGS))
# ccflags-sch_cn.o := -spam -mno-sse
ccflags-y := -msse2
default:
	@$(MAKE) -C $(KDIR) M=$(PWD) modules

install:
	install -v -m 644 sch_cn.ko $(IDIR)
	depmod "$(KERNEL_VERSION)"
	[ "$(KERNEL_VERSION)" != `uname -r` ] || modprobe sch_cn

clean:
	@$(MAKE) -C $(KDIR) M=$(PWD) clean

obj-m := sch_cn.o
