# Makefile – makefile of e1k driver

# if KERNELRELEASE is not defined, we've been called directly from the command line.
# Invoke the kernel build system.
UNAME := $(shell uname -r)

ifeq (${KERNELRELEASE},)
	KERNEL_SOURCE := /usr/src/linux-headers-${UNAME}
	PWD := $(shell pwd)

default:
	${MAKE} -C ${KERNEL_SOURCE} SUBDIRS=${PWD} modules

clean:
	${MAKE} -C ${KERNEL_SOURCE} SUBDIRS=${PWD} clean

# Otherwise KERNELRELEASE is defined; we've been invoked from the
# kernel build system and can use its language.
else
	obj-m += e1k.o
endif
