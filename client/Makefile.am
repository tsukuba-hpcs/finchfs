bin_PROGRAMS = finchmkdir

AM_CPPFLAGS = -g -Wall -pthread -I$(top_srcdir)/include @UCX_CFLAGS@
AM_LDFLAGS = -pthread
LDADD = $(top_builddir)/lib/libfinchfs.la @UCX_LIBS@

if FINCH_ZPOLINE_SUPPORT
nodist_bin_SCRIPTS = finchrun
lib_LTLIBRARIES = libfinchrun.la
libfinchrun_la_SOURCES = libfinchrun.c
libfinchrun_la_LDFLAGS = -shared -fPIC
libfinchrun_la_LIBADD = $(top_builddir)/lib/libfinchfs.la @UCX_LIBS@

install-exec-hook:
	make -C zpoline
	$(INSTALL) -m 755 zpoline/libzpoline.so $(prefix)/lib/
endif
