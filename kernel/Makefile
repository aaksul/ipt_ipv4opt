ifneq ($(KERNELRELEASE),)
# kbuild part of makefile
obj-m  := xt_ipv4option.o
xt_ipv4option-y := xt_ipv4opt.o

else
# normal makefile
KDIR := /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

endif