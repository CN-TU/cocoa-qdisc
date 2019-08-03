KERNEL_VERSION := $(shell uname -r)
IDIR := /lib/modules/$(KERNEL_VERSION)/kernel/net/sched/
KDIR := /lib/modules/$(KERNEL_VERSION)/build
PWD := $(shell pwd)
VERSION := $(shell git rev-parse HEAD 2>/dev/null)
default:
	@$(MAKE) -C $(KDIR) M=$(PWD) modules $(if $(VERSION),LDFLAGS_MODULE="--build-id=0x$(VERSION)" CFLAGS_MODULE="-DCN_VERSION=\\\"$(VERSION)\\\"")

install:
	install -v -m 644 sch_cn.ko $(IDIR)
	depmod "$(KERNEL_VERSION)"
	[ "$(KERNEL_VERSION)" != `uname -r` ] || modprobe sch_cn

clean:
	@$(MAKE) -C $(KDIR) M=$(PWD) clean
