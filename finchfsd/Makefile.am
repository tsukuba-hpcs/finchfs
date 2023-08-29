sbin_PROGRAMS = finchfsd
finchfsd_SOURCES = finchfsd.c fs_server.c hashmap.c fs_posix.c
noinst_HEADERS = hashmap.h fs.h

AM_CPPFLAGS = -g -Wall -pthread -I$(top_srcdir)/lib @MPI_CFLAGS@ @UCX_CFLAGS@
AM_LDFLAGS = -pthread
LDADD = $(top_builddir)/lib/libfinchfs.la @MPI_LIBS@ @UCX_LIBS@