/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */

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

#include <nm-setting-vpn.h>
#include "nm-openconnect-service.h"
#include "nm-utils.h"

G_DEFINE_TYPE (NMOPENCONNECTPlugin, nm_openconnect_plugin, NM_TYPE_VPN_PLUGIN)

typedef struct {
	GPid pid;
} NMOPENCONNECTPluginPrivate;

#define NM_OPENCONNECT_PLUGIN_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_OPENCONNECT_PLUGIN, NMOPENCONNECTPluginPrivate))

static const char *openconnect_binary_paths[] =
{
	"/usr/bin/openconnect",
	"/usr/local/bin/openconnect",
	"/opt/bin/openconnect",
	NULL
};

#define NM_OPENCONNECT_HELPER_PATH		LIBEXECDIR"/nm-openconnect-service-openconnect-helper"

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
	{ NM_OPENCONNECT_KEY_USERNAME,    G_TYPE_STRING, 0, 0 },
	{ NM_OPENCONNECT_KEY_XMLCONFIG,   G_TYPE_STRING, 0, 0 },
	{ NM_OPENCONNECT_KEY_PRIVKEY,     G_TYPE_STRING, 0, 0 },
	{ NM_OPENCONNECT_KEY_CERTSIGS,    G_TYPE_STRING, 0, 0 },
	{ NM_OPENCONNECT_KEY_LASTHOST,    G_TYPE_STRING, 0, 0 },
	{ NM_OPENCONNECT_KEY_MTU,         G_TYPE_STRING, 0, 0 },
	{ NM_OPENCONNECT_KEY_AUTOCONNECT, G_TYPE_BOOLEAN, 0, 0 },
	{ NULL,                           G_TYPE_NONE, 0, 0 }
};

static ValidProperty valid_secrets[] = {
	{ NM_OPENCONNECT_KEY_COOKIE,  G_TYPE_STRING, 0, 0 },
	{ NM_OPENCONNECT_KEY_GATEWAY, G_TYPE_STRING, 0, 0 },
	{ NULL,                       G_TYPE_NONE, 0, 0 }
};

static uid_t tun_owner;
static gid_t tun_group;
static char *tun_name = NULL;

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
			             "invalid integer property '%s' or out of range [%d -> %d]",
			             key, prop.int_min, prop.int_max);
			break;
		case G_TYPE_BOOLEAN:
			if (!strcmp (value, "yes") || !strcmp (value, "no"))
				return; /* valid */

			g_set_error (info->error,
			             NM_VPN_PLUGIN_ERROR,
			             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
			             "invalid boolean property '%s' (not yes or no)",
			             key);
			break;
		default:
			g_set_error (info->error,
			             NM_VPN_PLUGIN_ERROR,
			             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
			             "unhandled property '%s' type %s",
			             key, g_type_name (prop.type));
			break;
		}
	}

	/* Did not find the property from valid_properties or the type did not match */
	if (!info->table[i].name && strncmp(key, "form:", 5)) {
		g_set_error (info->error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
		             "property '%s' invalid or not supported",
		             key);
	}
}

static gboolean
nm_openconnect_properties_validate (NMSettingVPN *s_vpn, GError **error)
{
	ValidateInfo info = { &valid_properties[0], error, FALSE };

	nm_setting_vpn_foreach_data_item (s_vpn, validate_one_property, &info);
	if (!info.have_items) {
		g_set_error (error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
		             "%s",
		             "No VPN configuration options.");
		return FALSE;
	}

	return *error ? FALSE : TRUE;
}

static gboolean
nm_openconnect_secrets_validate (NMSettingVPN *s_vpn, GError **error)
{
	ValidateInfo info = { &valid_secrets[0], error, FALSE };

	nm_setting_vpn_foreach_secret (s_vpn, validate_one_property, &info);
	if (!info.have_items) {
		g_set_error (error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
		             "%s",
		             "No VPN secrets!");
		return FALSE;
	}

	return *error ? FALSE : TRUE;
}

static void openconnect_drop_child_privs(gpointer user_data)
{
	if (tun_name) {
		initgroups(NM_OPENCONNECT_USER, tun_group);
		setuid((uid_t)tun_owner);
	}
}

static void
openconnect_watch_cb (GPid pid, gint status, gpointer user_data)
{
	NMOPENCONNECTPlugin *plugin = NM_OPENCONNECT_PLUGIN (user_data);
	NMOPENCONNECTPluginPrivate *priv = NM_OPENCONNECT_PLUGIN_GET_PRIVATE (plugin);
	guint error = 0;

	if (WIFEXITED (status)) {
		error = WEXITSTATUS (status);
		if (error != 0)
			nm_warning ("openconnect exited with error code %d", error);
	}
	else if (WIFSTOPPED (status))
		nm_warning ("openconnect stopped unexpectedly with signal %d", WSTOPSIG (status));
	else if (WIFSIGNALED (status))
		nm_warning ("openconnect died with signal %d", WTERMSIG (status));
	else
		nm_warning ("openconnect died from an unknown cause");

	/* Reap child if needed. */
	waitpid (priv->pid, NULL, WNOHANG);
	priv->pid = 0;

	/* Must be after data->state is set since signals use data->state */
	switch (error) {
	case 2:
		/* Couldn't log in due to bad user/pass */
		nm_vpn_plugin_failure (NM_VPN_PLUGIN (plugin), NM_VPN_PLUGIN_FAILURE_LOGIN_FAILED);
		break;
	case 1:
		/* Other error (couldn't bind to address, etc) */
		nm_vpn_plugin_failure (NM_VPN_PLUGIN (plugin), NM_VPN_PLUGIN_FAILURE_CONNECT_FAILED);
		break;
	default:
		break;
	}

	nm_vpn_plugin_set_state (NM_VPN_PLUGIN (plugin), NM_VPN_SERVICE_STATE_STOPPED);
}

static gint
nm_openconnect_start_openconnect_binary (NMOPENCONNECTPlugin *plugin,
										 NMSettingVPN *s_vpn,
										 GError **error)
{
	GPid	pid;
	const char **openconnect_binary = NULL;
	GPtrArray *openconnect_argv;
	GSource *openconnect_watch;
	gint	stdin_fd;
	const char *props_vpn_gw, *props_cookie, *props_cacert, *props_mtu;
	
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
		             "Could not find openconnect binary.");
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
		             "No VPN gateway specified.");
		return -1;
	}

	props_cookie = nm_setting_vpn_get_secret (s_vpn, NM_OPENCONNECT_KEY_COOKIE);
	if (!props_cookie || !strlen (props_cookie)) {
		g_set_error (error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_LAUNCH_FAILED,
		             "%s",
		             "No WebVPN cookie provided.");
		return -1;
	}

	props_cacert = nm_setting_vpn_get_data_item (s_vpn, NM_OPENCONNECT_KEY_CACERT);
	props_mtu = nm_setting_vpn_get_data_item (s_vpn, NM_OPENCONNECT_KEY_MTU);

	openconnect_argv = g_ptr_array_new ();
	g_ptr_array_add (openconnect_argv, (gpointer) (*openconnect_binary));

	if (props_cacert && strlen(props_cacert)) {
		g_ptr_array_add (openconnect_argv, (gpointer) "--cafile");
		g_ptr_array_add (openconnect_argv, (gpointer) props_cacert);
	}

	if (props_mtu && strlen(props_mtu)) {
		g_ptr_array_add (openconnect_argv, (gpointer) "--mtu");
		g_ptr_array_add (openconnect_argv, (gpointer) props_mtu);
	}

	g_ptr_array_add (openconnect_argv, (gpointer) "--syslog");
	g_ptr_array_add (openconnect_argv, (gpointer) "--cookie-on-stdin");

	g_ptr_array_add (openconnect_argv, (gpointer) "--script");
	g_ptr_array_add (openconnect_argv, (gpointer) NM_OPENCONNECT_HELPER_PATH);

	if (tun_name) {
		g_ptr_array_add (openconnect_argv, (gpointer) "--interface");
		g_ptr_array_add (openconnect_argv, (gpointer) tun_name);
	}

	g_ptr_array_add (openconnect_argv, (gpointer) props_vpn_gw);

	g_ptr_array_add (openconnect_argv, NULL);

	if (!g_spawn_async_with_pipes (NULL, (char **) openconnect_argv->pdata, NULL,
								   G_SPAWN_DO_NOT_REAP_CHILD,
								   openconnect_drop_child_privs, NULL,
								   &pid, &stdin_fd, NULL, NULL, error)) {
		g_ptr_array_free (openconnect_argv, TRUE);
		nm_warning ("openconnect failed to start.  error: '%s'", (*error)->message);
		return -1;
	}
	g_ptr_array_free (openconnect_argv, TRUE);

	nm_info ("openconnect started with pid %d", pid);

	if (write(stdin_fd, props_cookie, strlen(props_cookie)) != strlen(props_cookie) ||
		write(stdin_fd, "\n", 1) != 1) {
		nm_warning ("openconnect didn't eat the cookie we fed it");
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
real_connect (NMVPNPlugin   *plugin,
              NMConnection  *connection,
              GError       **error)
{
	NMSettingVPN *s_vpn;
	gint openconnect_fd = -1;

	s_vpn = NM_SETTING_VPN (nm_connection_get_setting (connection, NM_TYPE_SETTING_VPN));
	g_assert (s_vpn);
	if (!nm_openconnect_properties_validate (s_vpn, error))
		goto out;
	if (!nm_openconnect_secrets_validate (s_vpn, error))
		goto out;

	openconnect_fd = nm_openconnect_start_openconnect_binary (NM_OPENCONNECT_PLUGIN (plugin), s_vpn, error);
	if (!openconnect_fd)
		return TRUE;

 out:
	return FALSE;
}

static gboolean
real_need_secrets (NMVPNPlugin *plugin,
                   NMConnection *connection,
                   char **setting_name,
                   GError **error)
{
	NMSettingVPN *s_vpn;

	g_return_val_if_fail (NM_IS_VPN_PLUGIN (plugin), FALSE);
	g_return_val_if_fail (NM_IS_CONNECTION (connection), FALSE);

	s_vpn = NM_SETTING_VPN (nm_connection_get_setting (connection, NM_TYPE_SETTING_VPN));
	if (!s_vpn) {
        g_set_error (error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_CONNECTION_INVALID,
		             "%s",
		             "Could not process the request because the VPN connection settings were invalid.");
		return FALSE;
	}

	/* We just need the WebVPN cookie, and the final IP address of the gateway
	   (after HTTP redirects, which do happen). All the certificate/SecurID 
	   nonsense can be handled for us, in the user's context, by auth-dialog */
	if (!nm_setting_vpn_get_data_item (s_vpn, NM_OPENCONNECT_KEY_GATEWAY)) {
		*setting_name = NM_SETTING_VPN_SETTING_NAME;
		return TRUE;
	}
	if (!nm_setting_vpn_get_secret (s_vpn, NM_OPENCONNECT_KEY_COOKIE)) {
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
real_disconnect (NMVPNPlugin   *plugin,
			  GError       **err)
{
	NMOPENCONNECTPluginPrivate *priv = NM_OPENCONNECT_PLUGIN_GET_PRIVATE (plugin);

	if (priv->pid) {
		if (kill (priv->pid, SIGTERM) == 0)
			g_timeout_add (2000, ensure_killed, GINT_TO_POINTER (priv->pid));
		else
			kill (priv->pid, SIGKILL);

		nm_info ("Terminated openconnect daemon with PID %d.", priv->pid);
		priv->pid = 0;
	}

	return TRUE;
}

static void
nm_openconnect_plugin_init (NMOPENCONNECTPlugin *plugin)
{
}

static void
nm_openconnect_plugin_class_init (NMOPENCONNECTPluginClass *openconnect_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (openconnect_class);
	NMVPNPluginClass *parent_class = NM_VPN_PLUGIN_CLASS (openconnect_class);

	g_type_class_add_private (object_class, sizeof (NMOPENCONNECTPluginPrivate));

	/* virtual methods */
	parent_class->connect    = real_connect;
	parent_class->need_secrets = real_need_secrets;
	parent_class->disconnect = real_disconnect;
}

NMOPENCONNECTPlugin *
nm_openconnect_plugin_new (void)
{
	return (NMOPENCONNECTPlugin *) g_object_new (NM_TYPE_OPENCONNECT_PLUGIN,
								   NM_VPN_PLUGIN_DBUS_SERVICE_NAME, NM_DBUS_SERVICE_OPENCONNECT,
								   NULL);
}

static void
quit_mainloop (NMOPENCONNECTPlugin *plugin, gpointer user_data)
{
	g_main_loop_quit ((GMainLoop *) user_data);
}

static void
create_persistent_tundev(void)
{
	struct passwd *pw;
	struct ifreq ifr;
	int fd;
	int i;

	pw = getpwnam(NM_OPENCONNECT_USER);
	if (!pw)
		return;

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
		if (tun_name)
			g_free(tun_name);

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
	tun_name = g_strdup(ifr.ifr_name);
	close(fd);
}

static void
destroy_persistent_tundev(void)
{
	struct ifreq ifr;
	int fd;

	if (!tun_name)
		return;

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
	close(fd);
}

int main (int argc, char *argv[])
{
	NMOPENCONNECTPlugin *plugin;
	GMainLoop *main_loop;

	g_type_init ();

	if (system ("/sbin/modprobe tun") == -1)
		exit (EXIT_FAILURE);

	create_persistent_tundev();

	plugin = nm_openconnect_plugin_new ();
	if (!plugin)
		exit (EXIT_FAILURE);

	main_loop = g_main_loop_new (NULL, FALSE);

	g_signal_connect (plugin, "quit",
				   G_CALLBACK (quit_mainloop),
				   main_loop);

	g_main_loop_run (main_loop);

	g_main_loop_unref (main_loop);
	g_object_unref (plugin);

	destroy_persistent_tundev();

	exit (EXIT_SUCCESS);
}
