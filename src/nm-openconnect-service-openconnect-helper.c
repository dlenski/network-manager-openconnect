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
 *   Copyright © 2008 - 2010 Intel Corporation.
 *
 * Based on nm-vpnc-service-vpnc-helper.c:
 *   Copyright © 2005 - 2010 Red Hat, Inc.
 *   Copyright © 2007 - 2008 Novell, Inc.
 */

#include <glib.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <NetworkManager.h>

#include "nm-openconnect-service.h"
#include "nm-utils.h"

static void
helper_failed (GDBusProxy *proxy, const char *reason)
{
	GError *err = NULL;

	g_warning ("nm-nopenconnect-service-openconnect-helper did not receive a valid %s from openconnect", reason);

	if (!g_dbus_proxy_call_sync (proxy, "SetFailure",
	                             g_variant_new ("(s)", reason),
	                             G_DBUS_CALL_FLAGS_NONE, -1,
	                             NULL,
	                             &err)) {
		g_warning ("Could not send failure information: %s", err->message);
		g_error_free (err);
	}

	exit (1);
}

static void
send_config (GDBusProxy *proxy, GVariant *config,
             GVariant *ip4config, GVariant *ip6config)
{
	GError *err = NULL;

	if (!g_dbus_proxy_call_sync (proxy, "SetConfig",
	                             g_variant_new ("(*)", config),
	                             G_DBUS_CALL_FLAGS_NONE, -1,
	                             NULL,
	                             &err))
		goto error;

	if (ip4config) {
		if (!g_dbus_proxy_call_sync (proxy, "SetIp4Config",
	                                     g_variant_new ("(*)", ip4config),
		                             G_DBUS_CALL_FLAGS_NONE, -1,
		                             NULL,
		                             &err))
			goto error;
	}

	if (ip6config) {
		if (!g_dbus_proxy_call_sync (proxy, "SetIp6Config",
	                                     g_variant_new ("(*)", ip6config),
		                             G_DBUS_CALL_FLAGS_NONE, -1,
		                             NULL,
		                             &err))
			goto error;
	}

	return;
error:
	g_warning ("Could not send configuration information: %s", err->message);
	g_error_free (err);
}


static GVariant *
str_to_gvariant (const char *str, gboolean try_convert)
{

	/* Empty */
	if (!str || strlen (str) < 1)
		return NULL;

	if (!g_utf8_validate (str, -1, NULL)) {
		if (try_convert && !(str = g_convert (str, -1, "ISO-8859-1", "UTF-8", NULL, NULL, NULL)))
			str = g_convert (str, -1, "C", "UTF-8", NULL, NULL, NULL);

		if (!str)
			/* Invalid */
			return NULL;
	}

	return g_variant_new_string (str);
}

static GVariant *
addr4_to_gvariant (const char *str)
{
	struct in_addr	temp_addr;

	/* Empty */
	if (!str || strlen (str) < 1)
		return NULL;

	if (inet_pton (AF_INET, str, &temp_addr) <= 0)
		return NULL;

	return g_variant_new_uint32 (temp_addr.s_addr);
}

static GVariant *
addr4_list_to_gvariant (const char *str)
{
	GVariantBuilder builder;
	char **split;
	int i;

	/* Empty */
	if (!str || strlen (str) < 1)
		return NULL;

	split = g_strsplit (str, " ", -1);
	if (g_strv_length (split) == 0)
		return NULL;

	g_variant_builder_init (&builder, G_VARIANT_TYPE_ARRAY);

	for (i = 0; split[i]; i++) {
		struct in_addr addr;

		if (inet_pton (AF_INET, split[i], &addr) > 0) {
			g_variant_builder_add_value (&builder, g_variant_new_uint32 (addr.s_addr));
		} else {
			g_strfreev (split);
			g_variant_unref (g_variant_builder_end (&builder));
			return NULL;
		}
	}

	g_strfreev (split);

	return g_variant_builder_end (&builder);
}

static GVariant *
addr6_to_gvariant (const char *str)
{
	struct in6_addr temp_addr;
	GVariantBuilder builder;
	int i;

	/* Empty */
	if (!str || strlen (str) < 1)
		return NULL;

	if (inet_pton (AF_INET6, str, &temp_addr) <= 0)
		return NULL;

	g_variant_builder_init (&builder, G_VARIANT_TYPE ("ay"));
	for (i = 0; i < sizeof (temp_addr); i++)
		g_variant_builder_add (&builder, "y", ((guint8 *) &temp_addr)[i]);
	return g_variant_builder_end (&builder);
}

static GVariant *
addr6_list_to_gvariant (const char *str)
{
	GVariantBuilder builder;
	char **split;
	int i;

	/* Empty */
	if (!str || strlen (str) < 1)
		return NULL;

	split = g_strsplit (str, " ", -1);
	if (g_strv_length (split) == 0)
		return NULL;

	g_variant_builder_init (&builder, G_VARIANT_TYPE ("aay"));

	for (i = 0; split[i]; i++) {
		GVariant *val = addr6_to_gvariant (split[i]);

		if (val) {
			g_variant_builder_add_value (&builder, val);
		} else {
			g_strfreev (split);
			g_variant_unref (g_variant_builder_end (&builder));
			return NULL;
		}
	}

	g_strfreev (split);

	return g_variant_builder_end (&builder);
}

static GVariant *
split_dns_list_to_gvariant (const char *str)
{
	gchar **split;

	if (!str || strlen (str) < 1)
		return NULL;

	split = g_strsplit (str, ",", -1);
	if (g_strv_length (split) == 0)
		return NULL;

	return g_variant_new_strv ((const gchar **) split, -1);
}

static GVariant *
get_ip4_routes (void)
{
	GVariantBuilder builder;
	GVariant *value;
	char *tmp;
	int num;
	int i;

#define BUFLEN 256

	tmp = getenv ("CISCO_SPLIT_INC");
	if (!tmp || strlen (tmp) < 1)
		return NULL;

	num = atoi (tmp);
	if (!num)
		return NULL;

	g_variant_builder_init (&builder, G_VARIANT_TYPE ("aau"));

	for (i = 0; i < num; i++) {
		GVariantBuilder array;
		char buf[BUFLEN];
		struct in_addr network;
		guint32 next_hop = 0; /* no next hop */
		guint32 prefix, metric = 0;

		snprintf (buf, BUFLEN, "CISCO_SPLIT_INC_%d_ADDR", i);
		tmp = getenv (buf);
		if (!tmp || inet_pton (AF_INET, tmp, &network) <= 0) {
			g_warning ("Ignoring invalid static route address '%s'", tmp ? tmp : "NULL");
			continue;
		}

		snprintf (buf, BUFLEN, "CISCO_SPLIT_INC_%d_MASKLEN", i);
		tmp = getenv (buf);
		if (tmp) {
			long int tmp_prefix;

			errno = 0;
			tmp_prefix = strtol (tmp, NULL, 10);
			if (errno || tmp_prefix <= 0 || tmp_prefix > 32) {
				g_warning ("Ignoring invalid static route prefix '%s'", tmp ? tmp : "NULL");
				continue;
			}
			prefix = (guint32) tmp_prefix;
		} else {
			struct in_addr netmask;

			snprintf (buf, BUFLEN, "CISCO_SPLIT_INC_%d_MASK", i);
			tmp = getenv (buf);
			if (!tmp || inet_pton (AF_INET, tmp, &netmask) <= 0) {
				g_warning ("Ignoring invalid static route netmask '%s'", tmp ? tmp : "NULL");
				continue;
			}
			prefix = nm_utils_ip4_netmask_to_prefix (netmask.s_addr);
		}

		g_variant_builder_init (&array, G_VARIANT_TYPE ("au"));
		g_variant_builder_add_value (&array, g_variant_new_uint32 (network.s_addr));
		g_variant_builder_add_value (&array, g_variant_new_uint32 (prefix));
		g_variant_builder_add_value (&array, g_variant_new_uint32 (next_hop));
		g_variant_builder_add_value (&array, g_variant_new_uint32 (metric));
		g_variant_builder_add_value (&builder, g_variant_builder_end (&array));
	}

	value = g_variant_builder_end (&builder);
	if (i > 1)
		return value;

	g_variant_unref (value);
	return NULL;
}

static GVariant *
get_ip6_routes (void)
{
	GVariant *value = NULL;
	GPtrArray *routes;
	char *tmp;
	int num;
	int i;

	tmp = getenv ("CISCO_IPV6_SPLIT_INC");
	if (!tmp || strlen (tmp) < 1)
		return NULL;

	num = atoi (tmp);
	if (!num)
		return NULL;

	routes = g_ptr_array_new_full (num, (GDestroyNotify) nm_ip_route_unref);

	for (i = 0; i < num; i++) {
		NMIPRoute *route;
		char buf[BUFLEN];
		char *network;
		guint32 prefix;
		GError *error = NULL;

		snprintf (buf, BUFLEN, "CISCO_IPV6_SPLIT_INC_%d_ADDR", i);
		network = getenv (buf);
		if (!network) {
			g_warning ("Ignoring invalid static route address '%s'", network ? network : "NULL");
			continue;
		}

		snprintf (buf, BUFLEN, "CISCO_IPV6_SPLIT_INC_%d_MASKLEN", i);
		tmp = getenv (buf);
		if (tmp) {
			long int tmp_prefix;

			errno = 0;
			tmp_prefix = strtol (tmp, NULL, 10);
			if (errno || tmp_prefix <= 0 || tmp_prefix > 128) {
				g_warning ("Ignoring invalid static route prefix '%s'", tmp ? tmp : "NULL");
				continue;
			}
			prefix = (guint32) tmp_prefix;
		} else {
			g_warning ("Ignoring static route %d with no prefix length", i);
			continue;
		}

		route = nm_ip_route_new (AF_INET6, network, prefix, NULL, -1, &error);
		if (!route) {
			g_warning ("Ignoring a route: %s", error->message);
			g_error_free (error);
			continue;
		}

		g_ptr_array_add (routes, route);
	}

	if (routes->len)
		value = nm_utils_ip6_routes_to_variant (routes);
	g_ptr_array_unref (routes);

	return value;
}

/*
 * Environment variables passed back from 'openconnect':
 *
 * VPNGATEWAY             -- vpn gateway address (always present)
 * TUNDEV                 -- tunnel device (always present)
 * INTERNAL_IP4_ADDRESS   -- address (always present)
 * INTERNAL_IP4_NETMASK   -- netmask (often unset)
 * INTERNAL_IP4_DNS       -- list of dns serverss
 * INTERNAL_IP4_NBNS      -- list of wins servers
 * CISCO_DEF_DOMAIN       -- default domain name
 * CISCO_BANNER           -- banner from server
 *
 */
int 
main (int argc, char *argv[])
{
	GDBusProxy *proxy;
	char *tmp;
	GVariantBuilder builder, ip4builder, ip6builder;
	GVariant *ip4config, *ip6config;
	GVariant *val;
	GError *err = NULL;
	struct in_addr temp_addr;

#if !GLIB_CHECK_VERSION (2, 35, 0)
	g_type_init ();
#endif

	/* openconnect gives us a "reason" code.  If we are given one,
	 * don't proceed unless its "connect".
	 */
	tmp = getenv ("reason");
	if (tmp && strcmp (tmp, "connect") != 0)
		exit (0);

	proxy = g_dbus_proxy_new_for_bus_sync (G_BUS_TYPE_SYSTEM,
	                                       G_DBUS_PROXY_FLAGS_NONE,
	                                       NULL,
	                                       NM_DBUS_SERVICE_OPENCONNECT,
	                                       NM_VPN_DBUS_PLUGIN_PATH,
	                                       NM_VPN_DBUS_PLUGIN_INTERFACE,
	                                       NULL, &err);
	if (!proxy) {
		g_warning ("Could not create a D-Bus proxy: %s", err->message);
		g_error_free (err);
		exit (1);
	}

	g_variant_builder_init (&builder, G_VARIANT_TYPE_VARDICT);
	g_variant_builder_init (&ip4builder, G_VARIANT_TYPE_VARDICT);
	g_variant_builder_init (&ip6builder, G_VARIANT_TYPE_VARDICT);

	/* Gateway */
	val = addr4_to_gvariant (getenv ("VPNGATEWAY"));
	if (!val)
		val = addr6_to_gvariant (getenv ("VPNGATEWAY"));
	if (val)
		g_variant_builder_add (&builder, "{sv}", NM_VPN_PLUGIN_CONFIG_EXT_GATEWAY, val);
	else
		helper_failed (proxy, "VPN Gateway");

	/* Tunnel device */
	val = str_to_gvariant (getenv ("TUNDEV"), FALSE);
	if (val)
		g_variant_builder_add (&builder, "{sv}", NM_VPN_PLUGIN_CONFIG_TUNDEV, val);
	else
		helper_failed (proxy, "Tunnel Device");

	/* Banner */
	val = str_to_gvariant (getenv ("CISCO_BANNER"), TRUE);
	if (val)
		g_variant_builder_add (&builder, "{sv}", NM_VPN_PLUGIN_CONFIG_BANNER, val);

	/* Default domain */
	val = str_to_gvariant (getenv ("CISCO_DEF_DOMAIN"), TRUE);
	if (val)
		g_variant_builder_add (&ip4builder, "{sv}", NM_VPN_PLUGIN_IP4_CONFIG_DOMAIN, val);

	/* MTU  */
	tmp = getenv ("INTERNAL_IP4_MTU");
	if (tmp && strlen (tmp)) {
		long int mtu;

		errno = 0;
		mtu = strtol (tmp, NULL, 10);
		if (errno || mtu < 0 || mtu > 20000) {
			g_warning ("Ignoring invalid tunnel MTU '%s'", tmp);
		} else {
			val = g_variant_new_uint32 ((guint32) mtu);
			g_variant_builder_add (&builder, "{sv}", NM_VPN_PLUGIN_CONFIG_MTU, val);
		}
	}

	/* IPv4 address */
	val = addr4_to_gvariant (getenv ("INTERNAL_IP4_ADDRESS"));
	if (val)
		g_variant_builder_add (&ip4builder, "{sv}", NM_VPN_PLUGIN_IP4_CONFIG_ADDRESS, val);
	else
		helper_failed (proxy, "IP4 Address");

	/* IPv4 PTP address; for openconnect PTP address == internal IPv4 address */
	val = addr4_to_gvariant (getenv ("INTERNAL_IP4_ADDRESS"));
	if (val)
		g_variant_builder_add (&ip4builder, "{sv}", NM_VPN_PLUGIN_IP4_CONFIG_PTP, val);
	else
		helper_failed (proxy, "IP4 PTP Address");

	/* IPv4 Netmask */
	tmp = getenv ("INTERNAL_IP4_NETMASK");
	if (tmp && inet_pton (AF_INET, tmp, &temp_addr) > 0) {
		val = g_variant_new_uint32 (nm_utils_ip4_netmask_to_prefix (temp_addr.s_addr));
		g_variant_builder_add (&ip4builder, "{sv}", NM_VPN_PLUGIN_IP4_CONFIG_PREFIX, val);
	}

	/* DNS */
	val = addr4_list_to_gvariant (getenv ("INTERNAL_IP4_DNS"));
	if (val)
		g_variant_builder_add (&ip4builder, "{sv}", NM_VPN_PLUGIN_IP4_CONFIG_DNS, val);

	/* WINS servers */
	val = addr4_list_to_gvariant (getenv ("INTERNAL_IP4_NBNS"));
	if (val)
		g_variant_builder_add (&ip4builder, "{sv}", NM_VPN_PLUGIN_IP4_CONFIG_NBNS, val);

	/* Split DNS domains */
	val = split_dns_list_to_gvariant (getenv ("CISCO_SPLIT_DNS"));
	if (val)
		g_variant_builder_add (&builder, "{sv}", NM_VPN_PLUGIN_IP4_CONFIG_DOMAINS, val);

	/* Routes */
	val = get_ip4_routes ();
	if (val) {
		g_variant_builder_add (&ip4builder, "{sv}", NM_VPN_PLUGIN_IP4_CONFIG_ROUTES, val);
		/* If routes-to-include were provided, that means no default route */
		g_variant_builder_add (&ip4builder, "{sv}", NM_VPN_PLUGIN_IP4_CONFIG_NEVER_DEFAULT,
		                       g_variant_new_boolean (TRUE));
	}

	/* IPv6 address */
	tmp = getenv ("INTERNAL_IP6_ADDRESS");
	if (tmp && strlen (tmp)) {
		val = addr6_to_gvariant (tmp);
		if (val)
			g_variant_builder_add (&ip6builder, "{sv}", NM_VPN_PLUGIN_IP6_CONFIG_ADDRESS, val);
		else
			helper_failed (proxy, "IP6 Address");
	}

	/* IPv6 PTP address; for openconnect PTP address == internal IPv6 address */
	tmp = getenv ("INTERNAL_IP6_ADDRESS");
	if (tmp && strlen (tmp)) {
		val = addr6_to_gvariant (tmp);
		if (val)
			g_variant_builder_add (&ip6builder, "{sv}", NM_VPN_PLUGIN_IP6_CONFIG_PTP, val);
		else
			helper_failed (proxy, "IP6 PTP Address");
	}

	/* IPv6 Netmask */
	tmp = getenv ("INTERNAL_IP6_NETMASK");
	if (tmp)
		tmp = strchr (tmp, '/');
	if (tmp) {
		val = g_variant_new_uint32 (strtol (tmp + 1, NULL, 10));
		g_variant_builder_add (&ip6builder, "{sv}", NM_VPN_PLUGIN_IP6_CONFIG_PREFIX, val);
	}

	/* DNS */
	val = addr6_list_to_gvariant (getenv ("INTERNAL_IP6_DNS"));
	if (val)
		g_variant_builder_add (&ip6builder, "{sv}", NM_VPN_PLUGIN_IP6_CONFIG_DNS, val);

	/* Routes */
	val = get_ip6_routes ();
	if (val) {
		g_variant_builder_add (&ip6builder, "{sv}", NM_VPN_PLUGIN_IP6_CONFIG_ROUTES, val);
		/* If routes-to-include were provided, that means no default route */
		g_variant_builder_add (&ip6builder, "{sv}", NM_VPN_PLUGIN_IP6_CONFIG_NEVER_DEFAULT,
		                       g_variant_new_boolean (TRUE));
	}

	ip4config = g_variant_builder_end (&ip4builder);

	if (g_variant_n_children (ip4config)) {
		val = g_variant_new_boolean (TRUE);
		g_variant_builder_add (&builder, "{sv}", NM_VPN_PLUGIN_CONFIG_HAS_IP4, val);
	} else {
		g_variant_unref (ip4config);
		ip4config = NULL;
	}

	ip6config = g_variant_builder_end (&ip6builder);

	if (g_variant_n_children (ip6config)) {
		val = g_variant_new_boolean (TRUE);
		g_variant_builder_add (&builder, "{sv}", NM_VPN_PLUGIN_CONFIG_HAS_IP6, val);
	} else {
		g_variant_unref (ip6config);
		ip6config = NULL;
	}

	/* Send the config info to nm-openconnect-service */
	send_config (proxy, g_variant_builder_end (&builder), ip4config, ip6config);

	g_object_unref (proxy);

	exit (0);
}
