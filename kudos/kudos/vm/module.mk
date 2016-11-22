# Makefile for the kernel module

# Set the module name
MODULE := vm

FILES :=

MIPSSRC += $(patsubst %, $(MODULE)/%, $(FILES))
X64SRC += $(patsubst %, $(MODULE)/%, $(FILES))

