# SPDX-License-Identifier: GPL-2.0-only
#
# ptwrite uprobe prototype sample.
#
# Module build (in-tree or via make M=samples/uprobe-ptwrite):
#   obj-$(CONFIG_SAMPLE_UPROBE_PTWRITE) += uprobe_ptwrite_test.o
#
# The userspace test target (test_prog) is built by the out-of-tree test
# harness (see /home/oc/uprobe-ptwrite-test); the harness computes the file
# offset of target()'s 5-byte NOP and passes it to the module's offset
# parameter.

obj-$(CONFIG_SAMPLE_UPROBE_PTWRITE) += uprobe_ptwrite_test.o
