AM_CPPFLAGS = \
	$(GLIB_CFLAGS) \
	$(LIBNM_CFLAGS) \
	-DBINDIR=\"$(bindir)\" \
	-DPREFIX=\""$(prefix)"\" \
	-DSYSCONFDIR=\""$(sysconfdir)"\" \
	-DLIBDIR=\""$(libdir)"\" \
	-DLIBEXECDIR=\""$(libexecdir)"\" \
	-DLOCALSTATEDIR=\""$(localstatedir)"\" \
	-DDATADIR=\"$(datadir)\" \
	-DNM_OPENCONNECT_LOCALEDIR=\"$(datadir)/locale\" \
	-I"$(top_srcdir)"/shared \
	$(NULL)

libexec_PROGRAMS = \
	nm-openconnect-service \
	nm-openconnect-service-openconnect-helper

nm_openconnect_service_SOURCES = \
	nm-openconnect-service.c \
	nm-openconnect-service.h \
	$(NULL)

nm_openconnect_service_LDADD = \
	$(GLIB_LIBS) \
	$(LIBNM_LIBS)


nm_openconnect_service_openconnect_helper_SOURCES = \
	nm-openconnect-service-openconnect-helper.c

nm_openconnect_service_openconnect_helper_LDADD = \
	$(GTHREAD_LIBS) \
	$(LIBNM_LIBS)

CLEANFILES = *~
