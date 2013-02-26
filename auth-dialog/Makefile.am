INCLUDES = -I${top_srcdir}

libexec_PROGRAMS = nm-openconnect-auth-dialog

nm_openconnect_auth_dialog_CPPFLAGS = \
	$(NM_CFLAGS) \
	$(GLIB_CFLAGS) \
	$(GTK_CFLAGS) \
	$(GCONF_CFLAGS) \
	$(OPENCONNECT_CFLAGS) \
	$(LIBXML_CFLAGS) \
	$(GNOMEKEYRING_CFLAGS) \
	-DICONDIR=\""$(datadir)/pixmaps"\" \
	-DBINDIR=\""$(bindir)"\" \
	-DG_DISABLE_DEPRECATED \
	-DGDK_DISABLE_DEPRECATED \
	-DGNOME_DISABLE_DEPRECATED \
	-DGNOMELOCALEDIR=\"$(datadir)/locale\" \
	-DVERSION=\"$(VERSION)\"

nm_openconnect_auth_dialog_SOURCES = \
	main.c \
	$(NULL)

nm_openconnect_auth_dialog_LDADD = \
	$(GTK_LIBS) \
	$(NM_LIBS) \
	$(GCONF_LIBS) \
	$(OPENCONNECT_LIBS) \
	$(LIBXML_LIBS) \
	$(GNOMEKEYRING_LIBS)

CLEANFILES = *~

