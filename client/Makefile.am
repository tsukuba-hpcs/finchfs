bin_PROGRAMS = finchfind finchmkdir

AM_CPPFLAGS = -g -Wall -pthread -I$(top_srcdir)/lib @UCX_CFLAGS@
AM_LDFLAGS = -pthread
LDADD = $(top_builddir)/lib/libfinchfs.la @UCX_LIBS@
