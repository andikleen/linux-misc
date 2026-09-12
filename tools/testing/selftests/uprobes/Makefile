# SPDX-License-Identifier: GPL-2.0
# ptwrite uprobe selftests (x86-64).
ARCH ?= $(shell uname -m 2>/dev/null || echo not)
CFLAGS += -O2 -Wall -no-pie

TEST_GEN_FILES := ptw_probe
TEST_PROGS := run_ptw.sh run_module.sh run_perfprobe.sh run_decode.sh

ifneq ($(filter x86 x86_64,$(ARCH)),)
TEST_GEN_FILES := ptw_probe
else
TEST_GEN_FILES :=
endif

include ../lib.mk
