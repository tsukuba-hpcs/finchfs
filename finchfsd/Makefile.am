sbin_PROGRAMS = finchfsd
finchfsd_SOURCES = finchfsd.c

AM_CPPFLAGS = -Wall -pthread -I$(top_srcdir)/lib @MPI_CFLAGS@ @UCX_CFLAGS@
AM_LDFLAGS = -pthread
LDADD = $(top_builddir)/lib/libfinchfs.la @MPI_LIBS@ @UCX_LIBS@