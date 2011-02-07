plugindir = $(libdir)/NetworkManager
plugin_LTLIBRARIES = libnm-openconnect-properties.la

libnm_openconnect_properties_la_SOURCES = \
	auth-helpers.c \
	auth-helpers.h \
	nm-openconnect.c \
	nm-openconnect.h

uidir = $(datadir)/gnome-vpn-properties/openconnect
ui_DATA = nm-openconnect-dialog.ui

libnm_openconnect_properties_la_CFLAGS =                \
        $(GTK_CFLAGS)                                   \
        $(GCONF_CFLAGS)                                 \
        $(NETWORKMANAGER_CFLAGS)                        \
        -DICONDIR=\""$(datadir)/pixmaps"\"              \
        -DUIDIR=\""$(uidir)"\"                          \
        -DG_DISABLE_DEPRECATED                          \
        -DGDK_DISABLE_DEPRECATED                        \
        -DGNOME_DISABLE_DEPRECATED                      \
        -DGNOMELOCALEDIR=\"$(datadir)/locale\"		\
        -DVERSION=\"$(VERSION)\"

libnm_openconnect_properties_la_LIBADD = \
        $(GTK_LIBS) \
        $(GCONF_LIBS) \
        $(NETWORKMANAGER_LIBS)

libnm_openconnect_properties_la_LDFLAGS =      \
        -avoid-version

CLEANFILES = *.bak *~

EXTRA_DIST =                            \
        $(ui_DATA)
