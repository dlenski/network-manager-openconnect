plugindir = $(libdir)/NetworkManager
plugin_LTLIBRARIES = libnm-vpn-plugin-openconnect.la
if WITH_GNOME
plugin_LTLIBRARIES += libnm-vpn-plugin-openconnect-editor.la
if WITH_LIBNM_GLIB
plugin_LTLIBRARIES += libnm-openconnect-properties.la
endif
endif

plugin_sources = \
	nm-openconnect-editor-plugin.c \
	nm-openconnect-editor-plugin.h \
	$(NULL)

editor_sources = \
	auth-helpers.c \
	auth-helpers.h \
	nm-openconnect-editor.c \
	nm-openconnect-editor.h
	$(NULL)

uidir = $(datadir)/gnome-vpn-properties/openconnect
if WITH_GNOME
ui_DATA = nm-openconnect-dialog.ui
endif

common_CFLAGS = \
	$(GLIB_CFLAGS) \
	$(OPENCONNECT_CFLAGS) \
	-I$(top_srcdir)/shared \
	-DICONDIR=\""$(datadir)/pixmaps"\" \
	-DUIDIR=\""$(uidir)"\" \
	-DLOCALEDIR=\"$(datadir)/locale\"

###############################################################################

libnm_vpn_plugin_openconnect_la_SOURCES = \
	$(top_srcdir)/shared/nm-utils/nm-vpn-editor-plugin-call.h \
	$(top_srcdir)/shared/nm-utils/nm-vpn-plugin-utils.c \
	$(top_srcdir)/shared/nm-utils/nm-vpn-plugin-utils.h \
	$(plugin_sources)

libnm_vpn_plugin_openconnect_la_CFLAGS = \
	-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_LIB_BASE \
	-DNM_PLUGIN_DIR=\"$(NM_PLUGIN_DIR)\" \
	$(common_CFLAGS) \
	$(LIBNM_CFLAGS)

libnm_vpn_plugin_openconnect_la_LIBADD = \
	$(LIBNM_LIBS) \
	$(OPENCONNECT_LIBS) \
	$(DL_LIBS) \
	$(NULL)

libnm_vpn_plugin_openconnect_la_LDFLAGS = \
	-avoid-version \
	-Wl,--version-script="$(srcdir)/libnm-vpn-plugin-openconnect.ver"

###############################################################################

libnm_vpn_plugin_openconnect_editor_la_SOURCES = \
	$(editor_sources)

libnm_vpn_plugin_openconnect_editor_la_CFLAGS = \
	-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_LIB_EDITOR \
	$(common_CFLAGS) \
	$(GTK_CFLAGS) \
	$(LIBNM_CFLAGS)

libnm_vpn_plugin_openconnect_editor_la_LIBADD = \
	$(GTK_LIBS) \
	$(LIBNM_LIBS) \
	$(OPENCONNECT_LIBS)

libnm_vpn_plugin_openconnect_editor_la_LDFLAGS = \
	-avoid-version \
	-Wl,--version-script="$(srcdir)/libnm-vpn-plugin-openconnect-editor.ver"

###############################################################################

libnm_openconnect_properties_la_SOURCES = \
	$(plugin_sources) \
	$(editor_sources)

libnm_openconnect_properties_la_CFLAGS = \
	-DNM_VPN_OLD \
	-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_LIB \
	$(common_CFLAGS) \
	$(GTK_CFLAGS) \
	$(LIBNM_GLIB_CFLAGS)

libnm_openconnect_properties_la_LIBADD = \
	$(GTK_LIBS) \
	$(LIBNM_GLIB_LIBS) \
	$(OPENCONNECT_LIBS)

libnm_openconnect_properties_la_LDFLAGS = \
	-avoid-version \
	-Wl,--version-script="$(srcdir)/libnm-openconnect-properties.ver"

###############################################################################

CLEANFILES = *.bak *~

EXTRA_DIST = \
	libnm-openconnect-properties.ver \
	libnm-vpn-plugin-openconnect.ver \
	libnm-vpn-plugin-openconnect-editor.ver \
	nm-openconnect-dialog.ui \
	$(NULL)
