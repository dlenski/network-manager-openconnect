INCLUDES = -I${top_srcdir}

libexec_PROGRAMS = nm-openconnect-auth-dialog

nm_openconnect_auth_dialog_CPPFLAGS = \
	$(NETWORKMANAGER_CFLAGS) \
	$(GTHREAD_CFLAGS) \
	$(GTK_CFLAGS) \
	$(GCONF_CFLAGS) \
	$(OPENCONNECT_CFLAGS) \
	$(GNOMEKEYRING_CFLAGS) \
	-DICONDIR=\""$(datadir)/pixmaps"\" \
	-DBINDIR=\""$(bindir)"\" \
	-DG_DISABLE_DEPRECATED \
	-DGDK_DISABLE_DEPRECATED \
	-DGNOME_DISABLE_DEPRECATED \
	-DGNOMELOCALEDIR=\"$(datadir)/locale\" \
	-DVERSION=\"$(VERSION)\"

nm_openconnect_auth_dialog_SOURCES = \
	auth-dlg-settings.h \
	main.c \
	$(NULL)

nm_openconnect_auth_dialog_LDADD = \
	$(GTK_LIBS) \
	$(NETWORKMANAGER_LIBS) \
	$(GCONF_LIBS) \
	$(OPENCONNECT_LIBS)

CLEANFILES = *~

