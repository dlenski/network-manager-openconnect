plugindir = $(libdir)/NetworkManager
plugin_LTLIBRARIES = libnm-vpn-plugin-openconnect.la
if WITH_LIBNM_GLIB
plugin_LTLIBRARIES += libnm-openconnect-properties.la
endif

uidir = $(datadir)/gnome-vpn-properties/openconnect
ui_DATA = nm-openconnect-dialog.ui

plugin_sources = \
	auth-helpers.c \
	auth-helpers.h \
	nm-openconnect.c \
	nm-openconnect.h
	$(NULL)

common_CFLAGS = \
	$(GLIB_CFLAGS) \
	$(GTK_CFLAGS) \
	$(OPENCONNECT_CFLAGS) \
	-I$(top_srcdir)/shared \
	-I$(top_srcdir)/src \
	-DICONDIR=\""$(datadir)/pixmaps"\" \
	-DUIDIR=\""$(uidir)"\" \
	-DLOCALEDIR=\"$(datadir)/locale\"

###############################################################################

libnm_vpn_plugin_openconnect_la_SOURCES = \
	$(plugin_sources)

libnm_vpn_plugin_openconnect_la_CFLAGS = \
	$(common_CFLAGS) \
	$(LIBNM_CFLAGS)

libnm_vpn_plugin_openconnect_la_LIBADD = \
	$(GTK_LIBS) \
	$(LIBNM_LIBS) \
	$(OPENCONNECT_LIBS)

libnm_vpn_plugin_openconnect_la_LDFLAGS = \
	-avoid-version

###############################################################################

libnm_openconnect_properties_la_SOURCES = \
	$(plugin_sources)

libnm_openconnect_properties_la_CFLAGS = \
	-DNM_VPN_OLD \
	$(common_CFLAGS) \
	$(LIBNM_GLIB_CFLAGS)

libnm_openconnect_properties_la_LIBADD = \
	$(GTK_LIBS) \
	$(LIBNM_GLIB_LIBS) \
	$(OPENCONNECT_LIBS)

libnm_openconnect_properties_la_LDFLAGS = \
	-avoid-version

###############################################################################

CLEANFILES = *.bak *~

EXTRA_DIST =                            \
	$(ui_DATA)
