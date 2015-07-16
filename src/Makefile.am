AM_CPPFLAGS = \
	$(DBUS_CFLAGS) \
	$(GLIB_CFLAGS) \
	$(LIBNM_GLIB_CFLAGS) \
	-DG_DISABLE_DEPRECATED \
	-DBINDIR=\"$(bindir)\" \
	-DPREFIX=\""$(prefix)"\" \
	-DSYSCONFDIR=\""$(sysconfdir)"\" \
	-DVERSION="\"$(VERSION)\"" \
	-DLIBDIR=\""$(libdir)"\" \
	-DLIBEXECDIR=\""$(libexecdir)"\" \
	-DLOCALSTATEDIR=\""$(localstatedir)"\" \
	-DDATADIR=\"$(datadir)\" \
	-DNM_OPENCONNECT_LOCALEDIR=\"$(datadir)/locale\"

libexec_PROGRAMS = \
	nm-openconnect-service \
	nm-openconnect-service-openconnect-helper

nm_openconnect_service_SOURCES = \
	nm-openconnect-service.c \
	nm-openconnect-service.h \
	nm-openconnect-service-defines.h

nm_openconnect_service_LDADD = \
	$(DBUS_LIBS) \
	$(GLIB_LIBS) \
	$(LIBNM_GLIB_LIBS)


nm_openconnect_service_openconnect_helper_SOURCES = \
	nm-openconnect-service-openconnect-helper.c

nm_openconnect_service_openconnect_helper_LDADD = \
	$(DBUS_LIBS) \
	$(GTHREAD_LIBS) \
	$(LIBNM_GLIB_LIBS)

CLEANFILES = *~
