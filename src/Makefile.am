INCLUDES = -I${top_srcdir} 

AM_CPPFLAGS = \
	$(DBUS_CFLAGS) \
	$(GTHREAD_CFLAGS) \
	$(NM_UTILS_CFLAGS) \
	-DG_DISABLE_DEPRECATED \
	-DBINDIR=\"$(bindir)\" \
	-DPREFIX=\""$(prefix)"\" \
	-DSYSCONFDIR=\""$(sysconfdir)"\" \
	-DVERSION="\"$(VERSION)\"" \
	-DLIBDIR=\""$(libdir)"\" \
	-DLIBEXECDIR=\""$(libexecdir)"\" \
	-DLOCALSTATEDIR=\""$(localstatedir)"\" \
	-DDATADIR=\"$(datadir)\"

libexec_PROGRAMS = nm-openconnect-service nm-openconnect-service-openconnect-helper

nm_openconnect_service_SOURCES = \
				nm-openconnect-service.c \
				nm-openconnect-service.h


nm_openconnect_service_LDADD = \
				$(DBUS_LIBS) \
				$(GTHREAD_LIBS) \
				$(NM_UTILS_LIBS)


nm_openconnect_service_openconnect_helper_SOURCES = \
				nm-openconnect-service-openconnect-helper.c

nm_openconnect_service_openconnect_helper_LDADD = \
				$(DBUS_LIBS) \
				$(GTHREAD_LIBS) \
				$(NM_UTILS_LIBS)

CLEANFILES = *~
