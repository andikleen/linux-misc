#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# link vmlinux
#
# vmlinux is linked from the objects selected by $(KBUILD_VMLINUX_INIT) and
# $(KBUILD_VMLINUX_MAIN) and $(KBUILD_VMLINUX_LIBS). Most are built-in.a files
# from top-level directories in the kernel tree, others are specified in
# arch/$(ARCH)/Makefile. Ordering when linking is important, and
# $(KBUILD_VMLINUX_INIT) must be first. $(KBUILD_VMLINUX_LIBS) are archives
# which are linked conditionally (not within --whole-archive), and do not
# require symbol indexes added.
#
# vmlinux
#   ^
#   |
#   +-< $(KBUILD_VMLINUX_INIT)
#   |   +--< init/version.o + more
#   |
#   +--< $(KBUILD_VMLINUX_MAIN)
#   |    +--< drivers/built-in.a mm/built-in.a + more
#   |
#   +--< $(KBUILD_VMLINUX_LIBS)
#   |    +--< lib/lib.a + more
#   |
#   +-< ${kallsymso} (see description in KALLSYMS section)
#
# vmlinux version (uname -v) cannot be updated during normal
# descending-into-subdirs phase since we do not yet know if we need to
# update vmlinux.
# Therefore this step is delayed until just before final link of vmlinux.
#
# System.map is generated to document addresses of all kernel symbols

# Error out on error
set -e

# Nice output in kbuild format
# Will be supressed by "make -s"
info()
{
	if [ "${quiet}" != "silent_" ]; then
		printf "  %-7s %s\n" ${1} ${2}
	fi
}

# Thin archive build here makes a final archive with symbol table and indexes
# from vmlinux objects INIT and MAIN, which can be used as input to linker.
# KBUILD_VMLINUX_LIBS archives should already have symbol table and indexes
# added.
#
# Traditional incremental style of link does not require this step
#
# built-in.a output file
#
archive_builtin()
{
	info AR built-in.a
	rm -f built-in.a;
	${AR} rcsTP${KBUILD_ARFLAGS} built-in.a			\
				${KBUILD_VMLINUX_INIT}		\
				${KBUILD_VMLINUX_MAIN}
}

# Link of vmlinux.o used for section mismatch analysis
# ${1} output file
modpost_link()
{
	local objects

	objects="--whole-archive				\
		built-in.a					\
		--no-whole-archive				\
		--start-group					\
		${KBUILD_VMLINUX_LIBS}				\
		--end-group"

	${LDFINAL} ${KBUILD_LDFLAGS} -r -o ${1} ${objects}
}

# Link of vmlinux
# ${1} - optional extra .o files
# ${2} - output file
vmlinux_link()
{
	local lds="${objtree}/${KBUILD_LDS}"
	local objects

	if [ "${SRCARCH}" != "um" ]; then
		objects="--whole-archive			\
			built-in.a				\
			--no-whole-archive			\
			--start-group				\
			${KBUILD_VMLINUX_LIBS}			\
			--end-group				\
			${1}"

		${LDFINAL} ${KBUILD_LDFLAGS} ${LDFLAGS_vmlinux} -o ${2}	\
			-T ${lds} ${objects}
	else
		objects="-Wl,--whole-archive			\
			built-in.a				\
			-Wl,--no-whole-archive			\
			-Wl,--start-group			\
			${KBUILD_VMLINUX_LIBS}			\
			-Wl,--end-group				\
			${1}"

		${CC} ${CFLAGS_vmlinux} -o ${2}			\
			-Wl,-T,${lds}				\
			${objects}				\
			-lutil -lrt -lpthread
		rm -f linux
	fi
}


# Create ${2} .o file with all symbols from the ${1} object file,
# passing optional options in ${3}
kallsyms()
{
	info KSYM ${2}
	local kallsymopt="${3}"

	if [ -n "${CONFIG_KALLSYMS_ALL}" ]; then
		kallsymopt="${kallsymopt} --all-symbols"
	fi

	if [ -n "${CONFIG_KALLSYMS_ABSOLUTE_PERCPU}" ]; then
		kallsymopt="${kallsymopt} --absolute-percpu"
	fi

	if [ -n "${CONFIG_KALLSYMS_BASE_RELATIVE}" ]; then
		kallsymopt="${kallsymopt} --base-relative"
	fi

	local aflags="${KBUILD_AFLAGS} ${KBUILD_AFLAGS_KERNEL}               \
		      ${NOSTDINC_FLAGS} ${LINUXINCLUDE} ${KBUILD_CPPFLAGS}"

	local afile="`basename ${2} .o`.S"
	(
	if $OBJDUMP --section-headers ${1} | grep -q \.gnu\.lto_ ; then
		$(srctree)/scripts/lto-nm ${1} 
	fi
	${NM} -n ${1} | awk 'NF == 3 { print }'
	)  | tee ${2}.kallsyms | ./scripts/kallsyms ${kallsymopt} > ${afile}
	${CC} ${aflags} -c -o ${2} ${afile}

}

# Create map file with all symbols from ${1}
# See mksymap for additional details
mksysmap()
{
	${CONFIG_SHELL} "${srctree}/scripts/mksysmap" ${1} ${2}
}

sortextable()
{
	${objtree}/scripts/sortextable ${1}
}

# Delete output files in case of error
cleanup()
{
	return 
	rm -f .tmp_System.map
	rm -f .tmp_kallsyms*
	rm -f .tmp_vmlinux*
	rm -f built-in.a
	rm -f System.map
	rm -f vmlinux
	rm -f vmlinux.o
}

on_exit()
{
	if [ $? -ne 0 ]; then
		cleanup
	fi
}
trap on_exit EXIT

on_signals()
{
	exit 1
}
trap on_signals HUP INT QUIT TERM

#
#
# Use "make V=1" to debug this script
case "${KBUILD_VERBOSE}" in
*1*)
	set -x
	;;
esac

if [ "$1" = "clean" ]; then
	cleanup
	exit 0
fi

# We need access to CONFIG_ symbols
case "${KCONFIG_CONFIG}" in
*/*)
	. "${KCONFIG_CONFIG}"
	;;
*)
	# Force using a file from the current directory
	. "./${KCONFIG_CONFIG}"
esac

# Update version
info GEN .version
if [ -r .version ]; then
	VERSION=$(expr 0$(cat .version) + 1)
	echo $VERSION > .version
else
	rm -f .version
	echo 1 > .version
fi;

# final build of init/
${MAKE} -f "${srctree}/scripts/Makefile.build" obj=init

archive_builtin

#link vmlinux.o
info LD vmlinux.o
modpost_link vmlinux.o

# modpost vmlinux.o to check for section mismatches
${MAKE} -f "${srctree}/scripts/Makefile.modpost" vmlinux.o

kallsymso=""
kallsyms_vmlinux=""

if [ -n "${CONFIG_KALLSYMS}" ] ; then
	# Generate kallsyms from the top level object files
	# this is slightly off, and has wrong addresses,
	# but gives us the conservative max length of the kallsyms
	# table to link in something with the size.
	info KALLSYMS1 .tmp_kallsyms1.o
	kallsyms "${KBUILD_VMLINUX_INIT} ${KBUILD_VMLINUX_MAIN}" \
		 .tmp_kallsyms1.o \
		 "--pad-file=.kallsyms_pad --ignore-overflow"
	kallsymsso=.tmp_kallsyms1.o
fi

info LDFINAL vmlinux
vmlinux_link "${kallsymsso}" vmlinux
if [ -n "${CONFIG_KALLSYMS}" ] ; then
	# Now regenerate the kallsyms table and patch it into the
	# previously linked file. We tell kallsyms to pad it
	# to the previous length, so that no symbol changes.
	info KALLSYMS2 .tmp_kallsyms2.o
	kallsyms vmlinux .tmp_kallsyms2.o $(<.kallsyms_pad)

	info OBJCOPY .tmp_kallsyms2.bin
	${OBJCOPY} -O binary .tmp_kallsyms2.o .tmp_kallsyms2.bin

	info PATCHFILE vmlinux
	EF=scripts/elf_file_offset
	if [ ! -r $EF ] ; then EF=source/$EF ; fi
	OFF=$(${OBJDUMP} --section-headers vmlinux |
	     gawk -f $EF \
	-v section=.kallsyms -v filesize=$(stat -c%s .tmp_kallsyms2.bin) )
	if [ -z "$OFF" ] ; then
		echo "Cannot find .kallsyms section in vmlinux binary"
		exit 1
	fi
	scripts/patchfile vmlinux $OFF .tmp_kallsyms2.bin
fi

if [ -n "${CONFIG_BUILDTIME_EXTABLE_SORT}" ]; then
	info SORTEX vmlinux
	sortextable vmlinux
fi

info SYSMAP System.map
mksysmap vmlinux System.map

# step a (see comment above)
if [ -n "${CONFIG_KALLSYMS}" ]; then
	mksysmap ${kallsyms_vmlinux} .tmp_System.map

	if ! cmp -s System.map .tmp_System.map; then
		echo >&2 Inconsistent kallsyms data
		echo >&2 Try "make KALLSYMS_EXTRA_PASS=1" as a workaround
		exit 1
	fi
fi
