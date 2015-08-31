/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager -- Network link manager
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 *   Copyright © 2008 - 2009 Intel Corporation.
 *
 * Based on nm-vpnc-service.c:
 *   Copyright © 2005 - 2008 Red Hat, Inc.
 *   Copyright © 2007 - 2008 Novell, Inc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <pwd.h>
#include <grp.h>
#include <locale.h>
#include <glib/gi18n.h>

#include "nm-openconnect-service.h"
#include "nm-utils.h"

#if !defined(DIST_VERSION)
# define DIST_VERSION VERSION
#endif

G_DEFINE_TYPE (NMOpenconnectPlugin, nm_openconnect_plugin, NM_TYPE_VPN_SERVICE_PLUGIN)

typedef struct {
	GPid pid;
	char *tun_name;
} NMOpenconnectPluginPrivate;

#define NM_OPENCONNECT_PLUGIN_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_OPENCONNECT_PLUGIN, NMOpenconnectPluginPrivate))

static const char *openconnect_binary_paths[] =
{
	"/usr/bin/openconnect",
	"/usr/sbin/openconnect",
	"/usr/local/bin/openconnect",
	"/usr/local/sbin/openconnect",
	"/opt/bin/openconnect",
	"/opt/sbin/openconnect",
	NULL
};

#define NM_OPENCONNECT_HELPER_PATH LIBEXECDIR"/nm-openconnect-service-openconnect-helper"

typedef struct {
	const char *name;
	GType type;
	gint int_min;
	gint int_max;
} ValidProperty;

static ValidProperty valid_properties[] = {
	{ NM_OPENCONNECT_KEY_GATEWAY,     G_TYPE_STRING, 0, 0 },
	{ NM_OPENCONNECT_KEY_CACERT,      G_TYPE_STRING, 0, 0 },
	{ NM_OPENCONNECT_KEY_AUTHTYPE,    G_TYPE_STRING, 0, 0 },
	{ NM_OPENCONNECT_KEY_USERCERT,    G_TYPE_STRING, 0, 0 },
	{ NM_OPENCONNECT_KEY_PRIVKEY,     G_TYPE_STRING, 0, 0 },
	{ NM_OPENCONNECT_KEY_MTU,         G_TYPE_STRING, 0, 0 },
	{ NM_OPENCONNECT_KEY_PEM_PASSPHRASE_FSID, G_TYPE_BOOLEAN, 0, 0 },
	{ NM_OPENCONNECT_KEY_PROXY,       G_TYPE_STRING, 0, 0 },
	{ NM_OPENCONNECT_KEY_CSD_ENABLE,  G_TYPE_BOOLEAN, 0, 0 },
	{ NM_OPENCONNECT_KEY_CSD_WRAPPER, G_TYPE_STRING, 0, 0 },
	{ NM_OPENCONNECT_KEY_TOKEN_MODE,  G_TYPE_STRING, 0, 0 },
	{ NM_OPENCONNECT_KEY_TOKEN_SECRET, G_TYPE_STRING, 0, 0 },
	{ NULL,                           G_TYPE_NONE, 0, 0 }
};

static ValidProperty valid_secrets[] = {
	{ NM_OPENCONNECT_KEY_COOKIE,  G_TYPE_STRING, 0, 0 },
	{ NM_OPENCONNECT_KEY_GATEWAY, G_TYPE_STRING, 0, 0 },
	{ NM_OPENCONNECT_KEY_GWCERT,  G_TYPE_STRING, 0, 0 },
	{ NULL,                       G_TYPE_NONE, 0, 0 }
};

static uid_t tun_owner;
static gid_t tun_group;
static gboolean debug = FALSE;
static GMainLoop *loop = NULL;

typedef struct ValidateInfo {
	ValidProperty *table;
	GError **error;
	gboolean have_items;
} ValidateInfo;

static void
validate_one_property (const char *key, const char *value, gpointer user_data)
{
	ValidateInfo *info = (ValidateInfo *) user_data;
	int i;

	if (*(info->error))
		return;

	info->have_items = TRUE;

	/* 'name' is the setting name; always allowed but unused */
	if (!strcmp (key, NM_SETTING_NAME))
		return;

	for (i = 0; info->table[i].name; i++) {
		ValidProperty prop = info->table[i];
		long int tmp;

		if (strcmp (prop.name, key))
			continue;

		switch (prop.type) {
		case G_TYPE_STRING:
			return; /* valid */
		case G_TYPE_INT:
			errno = 0;
			tmp = strtol (value, NULL, 10);
			if (errno == 0 && tmp >= prop.int_min && tmp <= prop.int_max)
				return; /* valid */

			g_set_error (info->error,
			             NM_VPN_PLUGIN_ERROR,
			             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
			             _("invalid integer property '%s' or out of range [%d -> %d]"),
			             key, prop.int_min, prop.int_max);
			break;
		case G_TYPE_BOOLEAN:
			if (!strcmp (value, "yes") || !strcmp (value, "no"))
				return; /* valid */

			g_set_error (info->error,
			             NM_VPN_PLUGIN_ERROR,
			             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
			             _("invalid boolean property '%s' (not yes or no)"),
			             key);
			break;
		default:
			g_set_error (info->error,
			             NM_VPN_PLUGIN_ERROR,
			             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
			             _("unhandled property '%s' type %s"),
			             key, g_type_name (prop.type));
			break;
		}
	}

	/* Did not find the property from valid_properties or the type did not match */
	if (!info->table[i].name && strncmp(key, "form:", 5)) {
		g_warning ("property '%s' unknown", key);
		if (0)
		g_set_error (info->error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
		             _("property '%s' invalid or not supported"),
		             key);
	}
}

static gboolean
nm_openconnect_properties_validate (NMSettingVpn *s_vpn, GError **error)
{
	ValidateInfo info = { &valid_properties[0], error, FALSE };

	nm_setting_vpn_foreach_data_item (s_vpn, validate_one_property, &info);
	if (!info.have_items) {
		g_set_error (error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
		             "%s",
		             _("No VPN configuration options."));
		return FALSE;
	}

	return *error ? FALSE : TRUE;
}

static gboolean
nm_openconnect_secrets_validate (NMSettingVpn *s_vpn, GError **error)
{
	ValidateInfo info = { &valid_secrets[0], error, FALSE };

	nm_setting_vpn_foreach_secret (s_vpn, validate_one_property, &info);
	if (!info.have_items) {
		g_set_error (error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
		             "%s",
		             _("No VPN secrets!"));
		return FALSE;
	}

	return *error ? FALSE : TRUE;
}

static char *
create_persistent_tundev(void)
{
	struct passwd *pw;
	struct ifreq ifr;
	int fd;
	int i;

	pw = getpwnam(NM_OPENCONNECT_USER);
	if (!pw)
		return NULL;

	tun_owner = pw->pw_uid;
	tun_group = pw->pw_gid;

	fd = open("/dev/net/tun", O_RDWR);
	if (fd < 0) {
		perror("open /dev/net/tun");
		exit(EXIT_FAILURE);
	}

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

	for (i = 0; i < 256; i++) {
		sprintf(ifr.ifr_name, "vpn%d", i);

		if (!ioctl(fd, TUNSETIFF, (void *)&ifr))
			break;
	}
	if (i == 256)
		exit(EXIT_FAILURE);

	if (ioctl(fd, TUNSETOWNER, tun_owner) < 0) {
		perror("TUNSETOWNER");
		exit(EXIT_FAILURE);
	}

	if (ioctl(fd, TUNSETPERSIST, 1)) {
		perror("TUNSETPERSIST");
		exit(EXIT_FAILURE);
	}
	close(fd);
	g_warning("Created tundev %s\n", ifr.ifr_name);
	return g_strdup(ifr.ifr_name);
}

static void
destroy_persistent_tundev(char *tun_name)
{
	struct ifreq ifr;
	int fd;

	fd = open("/dev/net/tun", O_RDWR);
	if (fd < 0) {
		perror("open /dev/net/tun");
		exit(EXIT_FAILURE);
	}

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
	strcpy(ifr.ifr_name, tun_name);

	if (ioctl(fd, TUNSETIFF, (void *)&ifr) < 0) {
		perror("TUNSETIFF");
		exit(EXIT_FAILURE);
	}

	if (ioctl(fd, TUNSETPERSIST, 0)) {
		perror("TUNSETPERSIST");
		exit(EXIT_FAILURE);
	}
	g_warning("Destroyed  tundev %s\n", tun_name);
	close(fd);
}

static void openconnect_drop_child_privs(gpointer user_data)
{
	char *tun_name = user_data;

	if (tun_name) {
		if (initgroups(NM_OPENCONNECT_USER, tun_group) ||
		    setgid(tun_group) || setuid(tun_owner)) {
			g_warning ("Failed to drop privileges when spawning openconnect");
			exit (1);
		}
	}
}

static void
openconnect_watch_cb (GPid pid, gint status, gpointer user_data)
{
	NMOpenconnectPlugin *plugin = NM_OPENCONNECT_PLUGIN (user_data);
	NMOpenconnectPluginPrivate *priv = NM_OPENCONNECT_PLUGIN_GET_PRIVATE (plugin);
	guint error = 0;

	if (WIFEXITED (status)) {
		error = WEXITSTATUS (status);
		if (error != 0)
			g_warning ("openconnect exited with error code %d", error);
	}
	else if (WIFSTOPPED (status))
		g_warning ("openconnect stopped unexpectedly with signal %d", WSTOPSIG (status));
	else if (WIFSIGNALED (status))
		g_warning ("openconnect died with signal %d", WTERMSIG (status));
	else
		g_warning ("openconnect died from an unknown cause");

	/* Reap child if needed. */
	waitpid (priv->pid, NULL, WNOHANG);
	priv->pid = 0;

	if (priv->tun_name) {
		destroy_persistent_tundev (priv->tun_name);
		g_free (priv->tun_name);
		priv->tun_name = NULL;
	}

	/* Must be after data->state is set since signals use data->state */
	switch (error) {
	case 2:
		/* Couldn't log in due to bad user/pass */
		nm_vpn_service_plugin_failure (NM_VPN_SERVICE_PLUGIN (plugin), NM_VPN_PLUGIN_FAILURE_LOGIN_FAILED);
		break;
	case 1:
		/* Other error (couldn't bind to address, etc) */
		nm_vpn_service_plugin_failure (NM_VPN_SERVICE_PLUGIN (plugin), NM_VPN_PLUGIN_FAILURE_CONNECT_FAILED);
		break;
	default:
		break;
	}

	nm_vpn_service_plugin_set_state (NM_VPN_SERVICE_PLUGIN (plugin), NM_VPN_SERVICE_STATE_STOPPED);
}

static gint
nm_openconnect_start_openconnect_binary (NMOpenconnectPlugin *plugin,
                                         NMSettingVpn *s_vpn,
                                         GError **error)
{
	NMOpenconnectPluginPrivate *priv = NM_OPENCONNECT_PLUGIN_GET_PRIVATE (plugin);
	GPid	pid;
	const char **openconnect_binary = NULL;
	GPtrArray *openconnect_argv;
	GSource *openconnect_watch;
	gint	stdin_fd;
	const char *props_vpn_gw, *props_cookie, *props_cacert, *props_mtu, *props_gwcert, *props_proxy;
	
	/* Find openconnect */
	openconnect_binary = openconnect_binary_paths;
	while (*openconnect_binary != NULL) {
		if (g_file_test (*openconnect_binary, G_FILE_TEST_EXISTS))
			break;
		openconnect_binary++;
	}

	if (!*openconnect_binary) {
		g_set_error (error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_LAUNCH_FAILED,
		             "%s",
		             _("Could not find openconnect binary."));
		return -1;
	}

	/* The actual gateway to use (after redirection) comes from the auth
	   dialog, so it's in the secrets hash not the properties */
	props_vpn_gw = nm_setting_vpn_get_secret (s_vpn, NM_OPENCONNECT_KEY_GATEWAY);
	if (!props_vpn_gw || !strlen (props_vpn_gw) ) {
		g_set_error (error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_LAUNCH_FAILED,
		             "%s",
		             _("No VPN gateway specified."));
		return -1;
	}

	props_cookie = nm_setting_vpn_get_secret (s_vpn, NM_OPENCONNECT_KEY_COOKIE);
	if (!props_cookie || !strlen (props_cookie)) {
		g_set_error (error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_LAUNCH_FAILED,
		             "%s",
		             _("No WebVPN cookie provided."));
		return -1;
	}
	props_gwcert = nm_setting_vpn_get_secret (s_vpn, NM_OPENCONNECT_KEY_GWCERT);

	props_cacert = nm_setting_vpn_get_data_item (s_vpn, NM_OPENCONNECT_KEY_CACERT);
	props_mtu = nm_setting_vpn_get_data_item (s_vpn, NM_OPENCONNECT_KEY_MTU);

	props_proxy = nm_setting_vpn_get_data_item (s_vpn, NM_OPENCONNECT_KEY_PROXY);

	openconnect_argv = g_ptr_array_new ();
	g_ptr_array_add (openconnect_argv, (gpointer) (*openconnect_binary));

	if (props_gwcert && strlen(props_gwcert)) {
		g_ptr_array_add (openconnect_argv, (gpointer) "--servercert");
		g_ptr_array_add (openconnect_argv, (gpointer) props_gwcert);
	} else if (props_cacert && strlen(props_cacert)) {
		g_ptr_array_add (openconnect_argv, (gpointer) "--cafile");
		g_ptr_array_add (openconnect_argv, (gpointer) props_cacert);
	}

	if (props_mtu && strlen(props_mtu)) {
		g_ptr_array_add (openconnect_argv, (gpointer) "--mtu");
		g_ptr_array_add (openconnect_argv, (gpointer) props_mtu);
	}

	if (props_proxy && strlen(props_proxy)) {
		g_ptr_array_add (openconnect_argv, (gpointer) "--proxy");
		g_ptr_array_add (openconnect_argv, (gpointer) props_proxy);
	}
		
	g_ptr_array_add (openconnect_argv, (gpointer) "--syslog");
	g_ptr_array_add (openconnect_argv, (gpointer) "--cookie-on-stdin");

	g_ptr_array_add (openconnect_argv, (gpointer) "--script");
	g_ptr_array_add (openconnect_argv, (gpointer) NM_OPENCONNECT_HELPER_PATH);

	priv->tun_name = create_persistent_tundev ();
	if (priv->tun_name) {
		g_ptr_array_add (openconnect_argv, (gpointer) "--interface");
		g_ptr_array_add (openconnect_argv, (gpointer) priv->tun_name);
	}

	g_ptr_array_add (openconnect_argv, (gpointer) props_vpn_gw);

	if (debug)
		g_ptr_array_add (openconnect_argv, (gpointer) "--verbose");

	g_ptr_array_add (openconnect_argv, NULL);

	if (!g_spawn_async_with_pipes (NULL, (char **) openconnect_argv->pdata, NULL,
	                               G_SPAWN_DO_NOT_REAP_CHILD,
	                               openconnect_drop_child_privs, priv->tun_name,
	                               &pid, &stdin_fd, NULL, NULL, error)) {
		g_ptr_array_free (openconnect_argv, TRUE);
		g_warning ("openconnect failed to start.  error: '%s'", (*error)->message);
		return -1;
	}
	g_ptr_array_free (openconnect_argv, TRUE);

	g_message ("openconnect started with pid %d", pid);

	if (write(stdin_fd, props_cookie, strlen(props_cookie)) != strlen(props_cookie) ||
	    write(stdin_fd, "\n", 1) != 1) {
		g_warning ("openconnect didn't eat the cookie we fed it");
		return -1;
	}

	close(stdin_fd);

	NM_OPENCONNECT_PLUGIN_GET_PRIVATE (plugin)->pid = pid;
	openconnect_watch = g_child_watch_source_new (pid);
	g_source_set_callback (openconnect_watch, (GSourceFunc) openconnect_watch_cb, plugin, NULL);
	g_source_attach (openconnect_watch, NULL);
	g_source_unref (openconnect_watch);

	return 0;
}
static gboolean
real_connect (NMVpnServicePlugin   *plugin,
              NMConnection  *connection,
              GError       **error)
{
	NMSettingVpn *s_vpn;
	gint openconnect_fd = -1;

	s_vpn = nm_connection_get_setting_vpn (connection);
	g_assert (s_vpn);
	if (!nm_openconnect_properties_validate (s_vpn, error))
		goto out;
	if (!nm_openconnect_secrets_validate (s_vpn, error))
		goto out;

	if (debug)
		nm_connection_dump (connection);

	openconnect_fd = nm_openconnect_start_openconnect_binary (NM_OPENCONNECT_PLUGIN (plugin), s_vpn, error);
	if (!openconnect_fd)
		return TRUE;

 out:
	return FALSE;
}

static gboolean
real_need_secrets (NMVpnServicePlugin *plugin,
                   NMConnection *connection,
                   const char **setting_name,
                   GError **error)
{
	NMSettingVpn *s_vpn;

	g_return_val_if_fail (NM_IS_VPN_SERVICE_PLUGIN (plugin), FALSE);
	g_return_val_if_fail (NM_IS_CONNECTION (connection), FALSE);

	s_vpn = nm_connection_get_setting_vpn (connection);
	if (!s_vpn) {
		g_set_error (error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_INVALID_CONNECTION,
		             "%s",
		             "Could not process the request because the VPN connection settings were invalid.");
		return FALSE;
	}

	/* We just need the WebVPN cookie, and the final IP address of the gateway
	   (after HTTP redirects, which do happen). All the certificate/SecurID 
	   nonsense can be handled for us, in the user's context, by auth-dialog */
	if (!nm_setting_vpn_get_secret (s_vpn, NM_OPENCONNECT_KEY_GATEWAY)) {
		*setting_name = NM_SETTING_VPN_SETTING_NAME;
		return TRUE;
	}
	if (!nm_setting_vpn_get_secret (s_vpn, NM_OPENCONNECT_KEY_COOKIE)) {
		*setting_name = NM_SETTING_VPN_SETTING_NAME;
		return TRUE;
	}
	if (!nm_setting_vpn_get_secret (s_vpn, NM_OPENCONNECT_KEY_GWCERT)) {
		*setting_name = NM_SETTING_VPN_SETTING_NAME;
		return TRUE;
	}
	return FALSE;
}

static gboolean
ensure_killed (gpointer data)
{
	int pid = GPOINTER_TO_INT (data);

	if (kill (pid, 0) == 0)
		kill (pid, SIGKILL);

	return FALSE;
}

static gboolean
real_disconnect (NMVpnServicePlugin   *plugin,
                 GError       **err)
{
	NMOpenconnectPluginPrivate *priv = NM_OPENCONNECT_PLUGIN_GET_PRIVATE (plugin);

	if (priv->pid) {
		if (kill (priv->pid, SIGTERM) == 0)
			g_timeout_add (2000, ensure_killed, GINT_TO_POINTER (priv->pid));
		else
			kill (priv->pid, SIGKILL);

		g_message ("Terminated openconnect daemon with PID %d.", priv->pid);
		priv->pid = 0;
	}

	return TRUE;
}

static void
nm_openconnect_plugin_init (NMOpenconnectPlugin *plugin)
{
}

static void
nm_openconnect_plugin_class_init (NMOpenconnectPluginClass *openconnect_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (openconnect_class);
	NMVpnServicePluginClass *parent_class = NM_VPN_SERVICE_PLUGIN_CLASS (openconnect_class);

	g_type_class_add_private (object_class, sizeof (NMOpenconnectPluginPrivate));

	/* virtual methods */
	parent_class->connect    = real_connect;
	parent_class->need_secrets = real_need_secrets;
	parent_class->disconnect = real_disconnect;
}

NMOpenconnectPlugin *
nm_openconnect_plugin_new (void)
{
	NMOpenconnectPlugin *plugin;
	GError *error = NULL;

	plugin = (NMOpenconnectPlugin *) g_initable_new (NM_TYPE_OPENCONNECT_PLUGIN, NULL, &error,
	                                                 NM_VPN_SERVICE_PLUGIN_DBUS_SERVICE_NAME, NM_DBUS_SERVICE_OPENCONNECT,
	                                                 NULL);
	if (!plugin) {
		g_warning ("Failed to initialize a plugin instance: %s", error->message);
		g_error_free (error);
	}

	return plugin;
}

static void
signal_handler (int signo)
{
	if (signo == SIGINT || signo == SIGTERM)
		g_main_loop_quit (loop);
}

static void
setup_signals (void)
{
	struct sigaction action;
	sigset_t mask;

	sigemptyset (&mask);
	action.sa_handler = signal_handler;
	action.sa_mask = mask;
	action.sa_flags = 0;
	sigaction (SIGTERM,  &action, NULL);
	sigaction (SIGINT,  &action, NULL);
}

static void
quit_mainloop (NMOpenconnectPlugin *plugin, gpointer user_data)
{
	g_main_loop_quit ((GMainLoop *) user_data);
}

int main (int argc, char *argv[])
{
	NMOpenconnectPlugin *plugin;

	gboolean persist = FALSE;
	GOptionContext *opt_ctx = NULL;

	GOptionEntry options[] = {
		{ "persist", 0, 0, G_OPTION_ARG_NONE, &persist, N_("Don't quit when VPN connection terminates"), NULL },
		{ "debug", 0, 0, G_OPTION_ARG_NONE, &debug, N_("Enable verbose debug logging (may expose passwords)"), NULL },
		{NULL}
	};

#if !GLIB_CHECK_VERSION (2, 35, 0)
	g_type_init ();
#endif

	/* locale will be set according to environment LC_* variables */
	setlocale (LC_ALL, "");

	bindtextdomain (GETTEXT_PACKAGE, NM_OPENCONNECT_LOCALEDIR);
	bind_textdomain_codeset (GETTEXT_PACKAGE, "UTF-8");
	textdomain (GETTEXT_PACKAGE);

	/* Parse options */
	opt_ctx = g_option_context_new (NULL);
	g_option_context_set_translation_domain (opt_ctx, GETTEXT_PACKAGE);
	g_option_context_set_ignore_unknown_options (opt_ctx, FALSE);
	g_option_context_set_help_enabled (opt_ctx, TRUE);
	g_option_context_add_main_entries (opt_ctx, options, NULL);

	g_option_context_set_summary (opt_ctx,
	                              _("nm-openconnect-service provides integrated "
	                                "Cisco AnyConnect SSL VPN capability to NetworkManager."));

	g_option_context_parse (opt_ctx, &argc, &argv, NULL);
	g_option_context_free (opt_ctx);

	if (getenv ("OPENCONNECT_DEBUG"))
		debug = TRUE;

	if (debug)
		g_message ("nm-openconnect-service (version " DIST_VERSION ") starting...");

	if (system ("/sbin/modprobe tun") == -1)
		exit (EXIT_FAILURE);

	plugin = nm_openconnect_plugin_new ();
	if (!plugin)
		exit (EXIT_FAILURE);

	loop = g_main_loop_new (NULL, FALSE);

	if (!persist)
		g_signal_connect (plugin, "quit", G_CALLBACK (quit_mainloop), loop);

	setup_signals ();
	g_main_loop_run (loop);

	g_main_loop_unref (loop);
	g_object_unref (plugin);

	exit (EXIT_SUCCESS);
}
