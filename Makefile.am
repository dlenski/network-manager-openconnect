AUTOMAKE_OPTIONS = foreign

SUBDIRS = src

if WITH_GNOME
SUBDIRS += properties po

if WITH_AUTHDLG
SUBDIRS += auth-dialog
endif
endif

dbusservicedir = $(sysconfdir)/dbus-1/system.d
dbusservice_DATA = nm-openconnect-service.conf

nmvpnservicedir = $(sysconfdir)/NetworkManager/VPN
nmvpnservice_DATA = nm-openconnect-service.name

nm-openconnect-service.name: $(srcdir)/nm-openconnect-service.name.in
	sed -e 's|[@]LIBEXECDIR[@]|$(libexecdir)|g' \
	    -e 's|[@]LIBDIR[@]|$(libdir)|g' \
	    $< >$@

DISTCHECK_CONFIGURE_FLAGS = --enable-more-warnings=yes

EXTRA_DIST = nm-openconnect-service.name.in \
             $(dbusservice_DATA)  \
             $(desktop_in_files)  \
             $(icon_DATA)         \
             intltool-extract.in  \
             intltool-merge.in    \
             intltool-update.in   \
             openconnect-strings.txt

CLEANFILES = $(nmvpnservice_DATA) $(desktop_DATA) *~
DISTCLEANFILES = intltool-extract intltool-merge intltool-update

ACLOCAL_AMFLAGS = -I m4
