#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.
AC_PREREQ([2.69])
AC_INIT([FINCHFS], [0.0.1])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AC_CONFIG_SRCDIR([README.md])
AC_CONFIG_HEADERS([lib/config.h])
AC_CONFIG_MACRO_DIRS([m4])

# Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O
AM_PROG_AR
LT_INIT

# Checks for libraries.
PKG_CHECK_MODULES([MPI], [ompi])
PKG_CHECK_MODULES([UCX], [ucx])

# Checks for header files.
AC_CHECK_HEADERS([stdlib.h string.h unistd.h stdint.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_INT32_T
AC_TYPE_MODE_T
AC_TYPE_OFF_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([fcntl.h stdlib.h string.h syslog.h unistd.h])

AC_DEFINE([DUMP_ADDR_FILE], ["/tmp/finchfsd"], [File path to dump address to])

AC_CONFIG_FILES([Makefile lib/Makefile finchfsd/Makefile pkgconfig/finchfs.pc pkgconfig/Makefile])
AC_OUTPUT
