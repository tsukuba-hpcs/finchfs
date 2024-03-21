sbin_PROGRAMS = finchfsd
finchfsd_SOURCES = finchfsd.c fs_server.c find.c
noinst_HEADERS = fs.h find.h

if USE_PMEMKV
finchfsd_SOURCES += fs_pmemkv.c
else
finchfsd_SOURCES += fs_posix.c
endif

AM_CPPFLAGS = -g -Wall -pthread -I$(top_srcdir)/lib @MPI_CFLAGS@ @UCX_CFLAGS@
AM_LDFLAGS = -pthread
LDADD = $(top_builddir)/lib/libfinchfs.la @MPI_LIBS@ @UCX_LIBS@

if USE_PMEMKV
AM_CPPFLAGS += @LIBPMEM_CFLAGS@ @LIBPMEMKV_CFLAGS@
LDADD += @LIBPMEM_LIBS@ @LIBPMEMKV_LIBS@
endif
