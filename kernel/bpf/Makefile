obj-y := core.o
obj-$(CONFIG_BPF_SYSCALL) += syscall.o verifier.o hashtab.o arraymap.o helpers.o
ifdef CONFIG_TEST_BPF
obj-$(CONFIG_BPF_SYSCALL) += test_stub.o
endif

# various version of gcc have a LTO bug where the &&labels used in the
# BPF interpreter can cause linker errors when spread incorrectly over
# partitions. Disable LTO for BPF for now
CFLAGS_core.o = $(DISABLE_LTO)
