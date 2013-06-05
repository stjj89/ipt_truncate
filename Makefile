MODULES_DIR := /lib/modules/$(shell uname -r)
KERNEL_DIR := ${MODULES_DIR}/build
obj-m += ipt_TRUNCATE.o

all:
	make -C ${KERNEL_DIR} M=$$PWD;
	make libipt_TRUNCATE.so
install: libipt_TRUNCATE.so ipt_TRUNCATE.ko
	cp ./libipt_TRUNCATE.so /lib/xtables/
	rm -rf /lib/modules/`uname -r`/ipt_TRUNCATE.ko
	ln -s `pwd`/ipt_TRUNCATE.ko /lib/modules/`uname -r`
	depmod -a
	modprobe ipt_TRUNCATE
#	insmod ./ipt_TRUNCATE.ko
modules:
	make -C ${KERNEL_DIR} M=$$PWD $@;
modules_install:
	make -C ${KERNEL_DIR} M=$$PWD $@;
libipt_TRUNCATE.so: libipt_TRUNCATE.o
	gcc -shared -fPIC -o $@ $^;
libipt_TRUNCATE.o: libipt_TRUNCATE.c
	gcc -O2 -Wall -D_INIT=lib$*_init -fPIC -c -o $@ $<;
clean:
	make -C ${KERNEL_DIR} M=$$PWD $@;
	rm -rf libipt_TRUNCATE.so libipt_TRUNCATE.o