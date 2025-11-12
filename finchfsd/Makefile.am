sbin_PROGRAMS = finchfsd
finchfsd_SOURCES = finchfsd.c fs_posix.c fs_server.c find.c
noinst_HEADERS = fs.h find.h

AM_CPPFLAGS = -g -Wall -pthread -I$(top_srcdir)/lib @MPI_CFLAGS@ @UCX_CFLAGS@ @LMDB_CFLAGS@
AM_LDFLAGS = -pthread
LDADD = $(top_builddir)/lib/libfinchfs.la @MPI_LIBS@ @UCX_LIBS@ @LMDB_LIBS@
