CURDIR = $(shell pwd)
CFLAGS += -I$(CURDIR)/..

all: iptables

install:
	$(MAKE) -C /home/aksulp/iptables/extensions install

iptables: cp_libipt4opt
	$(MAKE) -C /home/aksulp/iptables/extensions CFLAGS+="$(CFLAGS)"

cp_libipt4opt:
	cp $(CURDIR)/libipt_ipv4opt.c $(CURRENT_DIR)/libipt_ipv4opt.c

