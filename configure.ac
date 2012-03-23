AC_PREREQ(2.52)

AC_INIT(NetworkManager-openconnect, 0.9.4.0, dcbw@redhat.com, NetworkManager-openconnect)
AM_INIT_AUTOMAKE([subdir-objects no-dist-gzip dist-bzip2])
AM_MAINTAINER_MODE

AC_CONFIG_MACRO_DIR([m4])

AC_CONFIG_HEADERS([config.h])

dnl
dnl Require programs
dnl
AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_INSTALL
AC_PROG_LIBTOOL

dnl
dnl Required headers
dnl
AC_HEADER_STDC
AC_CHECK_HEADERS(fcntl.h paths.h sys/ioctl.h sys/time.h syslog.h unistd.h)

dnl
dnl Checks for typedefs, structures, and compiler characteristics.
dnl
AC_TYPE_MODE_T
AC_TYPE_PID_T
AC_HEADER_TIME

dnl
dnl Checks for library functions.
dnl
AC_PROG_GCC_TRADITIONAL
AC_FUNC_MEMCMP
AC_CHECK_FUNCS(select socket uname)

dnl
dnl GNOME support
dnl
AC_ARG_WITH(gnome, AS_HELP_STRING([--without-gnome], [Build NetworkManager-openconnect without GNOME support, e.g. vpn service only]))
AM_CONDITIONAL(WITH_GNOME, test x"$with_gnome" != xno)

AC_ARG_WITH(authdlg, AS_HELP_STRING([--without-authdlg], [Build NetworkManager-openconnect without authentication dialog]))
AM_CONDITIONAL(WITH_AUTHDLG, test x"$with_authdlg" != xno)

GETTEXT_PACKAGE=NetworkManager-openconnect
AC_SUBST(GETTEXT_PACKAGE)
AC_DEFINE_UNQUOTED(GETTEXT_PACKAGE,"$GETTEXT_PACKAGE", [Gettext package])

IT_PROG_INTLTOOL([0.35])
AM_GLIB_GNU_GETTEXT

PKG_CHECK_MODULES(GTHREAD, gthread-2.0)
AC_SUBST(GTHREAD_CFLAGS)
AC_SUBST(GTHREAD_LIBS)

PKG_CHECK_MODULES(LIBXML, libxml-2.0)
AC_SUBST(LIBXML_CFLAGS)
AC_SUBST(LIBXML_LIBS)

PKG_CHECK_MODULES(DBUS, dbus-glib-1 >= 0.74)
AC_SUBST(DBUS_CFLAGS)
AC_SUBST(DBUS_LIBS)

if test x"$with_gnome" != xno; then
	AC_ARG_WITH([gtkver], AS_HELP_STRING([--with-gtkver], [The major version of GTK+ to build with]),
	            with_gtkver="$withval",with_gtkver=0)

	gtk2_req=2.24
	gtk3_req=2.91.4
	case "${with_gtkver}" in
	       0) PKG_CHECK_MODULES(GTK, gtk+-3.0 > $gtk3_req, ,
	                            [PKG_CHECK_MODULES(GTK, gtk+-2.0 > $gtk2_req)])
		  ;;
	       2) PKG_CHECK_MODULES(GTK, gtk+-2.0 >= $gtk2_req)
	          ;;
	       3) PKG_CHECK_MODULES(GTK, gtk+-3.0 >= $gtk3_req)
	          ;;
	       *) AC_MSG_ERROR(unknown GTK+ version $with_gtkver!)
	          ;;
	esac
	AC_SUBST(GTK_CFLAGS)
	AC_SUBST(GTK_LIBS)

	PKG_CHECK_MODULES(GCONF, gconf-2.0)
	AC_SUBST(GCONF_CFLAGS)
	AC_SUBST(GCONF_LIBS)

	if test x"$with_authdlg" != xno; then
		PKG_CHECK_MODULES(OPENCONNECT, openconnect)
		AC_SUBST(OPENCONNECT_CFLAGS)
		AC_SUBST(OPENCONNECT_LIBS)
	fi
fi

PKG_CHECK_MODULES(NM,
                  NetworkManager >= 0.9.4
                  libnm-util >= 0.9.4
                  libnm-glib  >= 0.9.4
                  libnm-glib-vpn >= 0.9.4)
AC_SUBST(NM_CFLAGS)
AC_SUBST(NM_LIBS)

NM_COMPILER_WARNINGS

AC_CONFIG_FILES([
Makefile
src/Makefile
auth-dialog/Makefile
properties/Makefile
po/Makefile.in
])
AC_OUTPUT
