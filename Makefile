obj-m += kmon.o
kmon-objs := kmon_module.o symbol_resolver.o hash_ops.o monitor.o proc_interface.o

KERNEL_DIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

all:
	make -C $(KERNEL_DIR) M=$(PWD) modules

clean:
	make -C $(KERNEL_DIR) M=$(PWD) clean

install: all
	sudo insmod kmon.ko

uninstall:
	sudo rmmod kmon

.PHONY: all clean install uninstall

