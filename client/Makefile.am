bin_PROGRAMS = finchfind finchmkdir
nodist_bin_SCRIPTS = finchrun

AM_CPPFLAGS = -g -Wall -pthread -I$(top_srcdir)/include @UCX_CFLAGS@
AM_LDFLAGS = -pthread
LDADD = $(top_builddir)/lib/libfinchfs.la @UCX_LIBS@

lib_LTLIBRARIES = libfinchrun.la
libfinchrun_la_SOURCES = libfinchrun.c
libfinchrun_la_LDFLAGS = -shared -fPIC
libfinchrun_la_LIBADD = $(top_builddir)/lib/libfinchfs.la @UCX_LIBS@

install-exec-hook:
	make -C zpoline
	$(INSTALL) -m 755 zpoline/libzpoline.so $(prefix)/lib/
