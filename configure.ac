AC_PREREQ(2.52)

AC_INIT(NetworkManager-openconnect, 1.1.0, dcbw@redhat.com, NetworkManager-openconnect)
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

AC_ARG_WITH(libnm-glib, AS_HELP_STRING([--without-libnm-glib], [Build NetworkManager-openconnect without libnm-glib comatibility]))
AM_CONDITIONAL(WITH_LIBNM_GLIB, test x"$with_libnm_glib" != xno)

AC_ARG_WITH(authdlg, AS_HELP_STRING([--without-authdlg], [Build NetworkManager-openconnect without authentication dialog]))
AM_CONDITIONAL(WITH_AUTHDLG, test x"$with_authdlg" != xno)

GETTEXT_PACKAGE=NetworkManager-openconnect
AC_SUBST(GETTEXT_PACKAGE)
AC_DEFINE_UNQUOTED(GETTEXT_PACKAGE,"$GETTEXT_PACKAGE", [Gettext package])

IT_PROG_INTLTOOL([0.35])
AM_GLIB_GNU_GETTEXT

PKG_CHECK_MODULES(GLIB, glib-2.0 >= 2.32)
GLIB_CFLAGS="$GLIB_CFLAGS -DGLIB_VERSION_MIN_REQUIRED=GLIB_VERSION_2_32"

PKG_CHECK_MODULES(LIBXML, libxml-2.0)

PKG_CHECK_MODULES(DBUS, dbus-glib-1 >= 0.74)

if test x"$with_gnome" != xno; then
	PKG_CHECK_MODULES(GTK, gtk+-3.0 >= 3.4)
	GTK_CFLAGS="$GTK_CFLAGS -DGDK_VERSION_MIN_REQUIRED=GDK_VERSION_3_4"

	PKG_CHECK_MODULES(LIBSECRET, libsecret-unstable)

	if test x"$with_authdlg" != xno; then
		PKG_CHECK_MODULES(OPENCONNECT, openconnect >= 3.02)
	fi

	if test x"$with_libnm_glib" != xno; then
		PKG_CHECK_MODULES(LIBNM_GLIB,
				  NetworkManager >= 1.1.0
				  libnm-util >= 1.1.0
				  libnm-glib  >= 1.1.0
				  libnm-glib-vpn >= 1.1.0)
	fi
fi

dnl
dnl Distribution version string
dnl
AC_ARG_WITH(dist-version, AS_HELP_STRING([--with-dist-version=<dist-version>], [Define the custom version (like distribution package name and revision)]), ac_distver=$withval, ac_distver="")
if ! test x"$ac_distver" = x""; then
  AC_DEFINE_UNQUOTED(DIST_VERSION, "$ac_distver", [Define the distribution version string])
fi

PKG_CHECK_MODULES(LIBNM, libnm >= 1.1.0)
LIBNM_CFLAGS="$LIBNM_CFLAGS -DNM_VERSION_MIN_REQUIRED=NM_VERSION_1_2"
LIBNM_CFLAGS="$LIBNM_CFLAGS -DNM_VERSION_MAX_ALLOWED=NM_VERSION_1_2"

NM_COMPILER_WARNINGS

AC_CONFIG_FILES([
Makefile
src/Makefile
auth-dialog/Makefile
properties/Makefile
po/Makefile.in
])
AC_OUTPUT
