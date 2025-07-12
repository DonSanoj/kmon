obj-m += kmon_module.o

KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
INSTALL_DIR := /lib/modules/$(shell uname -r)/kernel/drivers/mymodules

all:
	make -C $(KDIR) M=$(PWD) modules

clean:
	make -C $(KDIR) M=$(PWD) clean

install:
	sudo mkdir -p $(INSTALL_DIR)
	sudo cp kmon_module.ko $(INSTALL_DIR)
	sudo depmod -a 
	@echo "kmon_module.ko installed to $(INSTALL_DIR)"


uninstall:
	sudo rm -f $(INSTALL_DIR)/kmon_module.ko
	sudo depmod -a
	@echo "kmon_module.ko removed from $(INSTALL_DIR)"

