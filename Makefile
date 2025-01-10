obj-m = rootkit.o
PWD := $(shell pwd)
EXTRA_CFLAGS = -Wall -g

all:
	$(MAKE) ARCH=arm64 CROSS_COMPILE=$(CROSS) -C $(KDIR) M=$(PWD) modules

test:
	gcc tester.c $(EXTRA_CFLAGS) -o tester

test-clean:
	rm -f tester

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
