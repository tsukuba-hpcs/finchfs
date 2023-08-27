lib_LTLIBRARIES = libfinchfs.la
include_HEADERS = finchfs.h
noinst_HEADERS = log.h fs_rpc.h path.h

libfinchfs_la_SOURCES = finchfs.c log.c fs_client.c path.c

AM_CPPFLAGS = -Wall -pthread @UCX_CFLAGS@
AM_LDFLAGS = -pthread @UCX_LIBS@
