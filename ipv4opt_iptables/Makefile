CURDIR = $(shell pwd)
CFLAGS += -I$(CURDIR)/..
PROJ_DIR := $(CURDIR)/..
HOME_DIR := $(PROJ_DIR)/..

all: libipt_ipv4opt

install:
	$(MAKE) -C $(HOME_DIR)/iptables/extensions install

clean:
	$(MAKE) -C $(HOME_DIR)/iptables/extensions clean

libipt_ipv4opt: cp_libipt_ipv4opt
	$(MAKE) -C $(HOME_DIR)/iptables/extensions CFLAGS+="$(CFLAGS)"

cp_libipt_ipv4opt:
	cp $(CURDIR)/libipt_ipv4opt.c $(HOME_DIR)/iptables/extensions/libipt_ipv4opt.c

