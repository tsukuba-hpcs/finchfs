#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.
AC_PREREQ([2.69])
AC_INIT([FINCHFS], [0.1.0])
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

AC_ARG_ENABLE([mmap],
  [AS_HELP_STRING([--enable-mmap], [Enable mmap support])],
  [if test "x$enable_mmap" = "xyes"; then
     AC_DEFINE([FINCH_MMAP_SUPPORT], 1, [Enable mmap support])
  fi],
  [enable_mmap=no])

AM_CONDITIONAL([FINCH_ZPOLINE_SUPPORT], [test x$enable_zpoline = xyes])
AC_ARG_ENABLE([zpoline],
  [AS_HELP_STRING([--enable-zpoline], [Enable zpoline support])],
  [if test "x$enable_zpoline" = "xyes"; then
     AC_DEFINE([FINCH_ZPOLINE_SUPPORT], 1, [Enable zpoline support])
  fi],
  [enable_zpoline=no])

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

AC_CONFIG_FILES([Makefile lib/Makefile finchfsd/Makefile pkgconfig/finchfs.pc pkgconfig/Makefile client/Makefile client/finchrun])
AC_OUTPUT
