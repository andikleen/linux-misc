#!/bin/bash
#
# link vmlinux
#
# vmlinux is linked from the objects selected by $(KBUILD_VMLINUX_INIT) and
# $(KBUILD_VMLINUX_MAIN). Most are built-in.o files from top-level directories
# in the kernel tree, others are specified in arch/$(ARCH)/Makefile.
# Ordering when linking is important, and $(KBUILD_VMLINUX_INIT) must be first.
#
# vmlinux
#   ^
#   |
#   +-< $(KBUILD_VMLINUX_INIT)
#   |   +--< init/version.o + more
#   |
#   +--< $(KBUILD_VMLINUX_MAIN)
#   |    +--< drivers/built-in.o mm/built-in.o + more
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

# Link of vmlinux.o used for section mismatch analysis
# ${1} output file
modpost_link()
{
	${LD} ${LDFLAGS} -r -o ${1} ${KBUILD_VMLINUX_INIT}                   \
		--start-group ${KBUILD_VMLINUX_MAIN} --end-group
}

# Link of vmlinux
# ${1} - optional extra .o files
# ${2} - output file
vmlinux_link()
{
	local lds="${objtree}/${KBUILD_LDS}"

	if [ "${SRCARCH}" != "um" ]; then
		${LDFINAL} ${LDFLAGS} ${LDFLAGS_vmlinux} -o ${2}                  \
			-T ${lds} ${KBUILD_VMLINUX_INIT}                     \
			--start-group ${KBUILD_VMLINUX_MAIN} --end-group ${1}
	else
		${CC} ${CFLAGS_vmlinux} -o ${2}                              \
			-Wl,-T,${lds} ${KBUILD_VMLINUX_INIT}                 \
			-Wl,--start-group                                    \
				 ${KBUILD_VMLINUX_MAIN}                      \
			-Wl,--end-group                                      \
			-lutil ${1}
		rm -f linux
	fi
}


# Create ${2} .o file with all symbols from the ${1} object file
kallsyms()
{
	info KSYM ${2}
	local kallsymopt;

	if [ -n "${CONFIG_HAVE_UNDERSCORE_SYMBOL_PREFIX}" ]; then
		kallsymopt="${kallsymopt} --symbol-prefix=_"
	fi

	if [ -n "${CONFIG_KALLSYMS_ALL}" ]; then
		kallsymopt="${kallsymopt} --all-symbols"
	fi

	if [ -n "${CONFIG_ARM}" ] && [ -n "${CONFIG_PAGE_OFFSET}" ]; then
		kallsymopt="${kallsymopt} --page-offset=$CONFIG_PAGE_OFFSET"
	fi
	kallsymopt="${kallsymopt} $3"

	local aflags="${KBUILD_AFLAGS} ${KBUILD_AFLAGS_KERNEL}               \
		      ${NOSTDINC_FLAGS} ${LINUXINCLUDE} ${KBUILD_CPPFLAGS}"

	${NM} -n ${1} | \
		awk 'NF == 3 { print}' |
		scripts/kallsyms ${kallsymopt} | \
		${CC} ${aflags} -c -o ${2} -x assembler-with-cpp -
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
trap cleanup SIGHUP SIGINT SIGQUIT SIGTERM ERR
cleanup()
{
	rm -f .old_version
	rm -f .tmp_System.map
	rm -f .tmp_kallsyms*
	rm -f .tmp_version
	rm -f .tmp_vmlinux*
	rm -f System.map
	rm -f vmlinux
	rm -f vmlinux.o
}

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

#link vmlinux.o
info LD vmlinux.o
modpost_link vmlinux.o

# modpost vmlinux.o to check for section mismatches
${MAKE} -f "${srctree}/scripts/Makefile.modpost" vmlinux.o

# Update version
info GEN .version
if [ ! -r .version ]; then
	rm -f .version;
	echo 1 >.version;
else
	mv .version .old_version;
	expr 0$(cat .old_version) + 1 >.version;
fi;

# final build of init/
${MAKE} -f "${srctree}/scripts/Makefile.build" obj=init

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
		 "--pad-file=.kallsyms_pad"
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
	scripts/patchfile vmlinux \
		$(./source/scripts/elf_file_offset vmlinux kallsyms_offset) \
		.tmp_kallsyms2.bin
fi

if [ -n "${CONFIG_BUILDTIME_EXTABLE_SORT}" ]; then
	info SORTEX vmlinux
	sortextable vmlinux
fi

info SYSMAP System.map
mksysmap vmlinux System.map

# We made a new kernel - delete old version file
rm -f .old_version
