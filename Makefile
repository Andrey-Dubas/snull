
DEBFLAGS = -O -g -Wno-declaration-after-statement

EXTRA_CFLAGS += $(DEBFLAGS)
EXTRA_CFLAGS += -I..


ifneq ($(KERNELRELEASE),)
obj-m := driver_main.o
else

KERNELDIR ?= /lib/modules/$(shell uname -r)/build
PWD       := $(shell pwd)

default:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules
endif


clean:
	rm -rf *.o *~ core .depend .*.cmd *.ko *.mod.c .tmp_versions
