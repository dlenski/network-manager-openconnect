AUTOMAKE_OPTIONS = foreign

SUBDIRS = shared properties src po

if WITH_GNOME
if WITH_AUTHDLG
SUBDIRS += auth-dialog
endif
endif

dbusservicedir = $(sysconfdir)/dbus-1/system.d
dbusservice_DATA = nm-openconnect-service.conf

nmvpnservicedir = $(NM_VPN_SERVICE_DIR)
nmvpnservice_DATA = nm-openconnect-service.name

if WITH_LIBNM_GLIB
# Install a file with full path to plugins for an old gnome-shell
# https://bugzilla.gnome.org/show_bug.cgi?id=693590
install-data-hook:
	mkdir -p $(DESTDIR)$(sysconfdir)/NetworkManager/VPN
	sed -e "1s|^|# This file is obsoleted by a file in $(NM_VPN_SERVICE_DIR)\n\n|" \
	    -e 's|[@]LIBEXECDIR[@]|$(libexecdir)|g' \
	    -e 's|[@]PLUGINDIR[@]|@NM_PLUGIN_DIR@|g' \
	    <$(srcdir)/nm-openconnect-service.name.in \
	    >$(DESTDIR)$(sysconfdir)/NetworkManager/VPN/nm-openconnect-service.name

uninstall-hook:
	 rm -f $(DESTDIR)$(sysconfdir)/NetworkManager/VPN/nm-openconnect-service.name
endif

appdatadir = $(datadir)/appdata
appdata_files = $(appdata_in_files:.xml.in=.xml)
if WITH_GNOME
appdata_DATA = $(appdata_in_files:.xml.in=.xml)
endif
appdata_in_files = appdata/network-manager-openconnect.metainfo.xml.in
@INTLTOOL_XML_RULE@

nm-openconnect-service.name: $(srcdir)/nm-openconnect-service.name.in
	sed -e 's|[@]LIBEXECDIR[@]|$(libexecdir)|g' \
	    -e 's|[@]PLUGINDIR[@]/|@NM_PLUGIN_DIR_NAME_FILE@|g' \
	    $< >$@

DISTCHECK_CONFIGURE_FLAGS = --enable-more-warnings=yes

EXTRA_DIST = nm-openconnect-service.name.in \
             $(dbusservice_DATA)  \
             $(desktop_in_files)  \
             $(icon_DATA)         \
             $(appdata_in_files)  \
             $(appdata_files)     \
             intltool-extract.in  \
             intltool-merge.in    \
             intltool-update.in   \
             openconnect-strings.txt

CLEANFILES = $(nmvpnservice_DATA) \
             $(desktop_DATA)      \
             $(appdata_files)

DISTCLEANFILES = intltool-extract intltool-merge intltool-update

ACLOCAL_AMFLAGS = -I m4
