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
#include <dbus/dbus.h>
#include <dbus/dbus-glib-lowlevel.h>
#include <dbus/dbus-glib.h>
#include <NetworkManager.h>

#include "nm-openconnect-service.h"
#include "nm-utils.h"

/* These are here because nm-dbus-glib-types.h isn't exported */
#define DBUS_TYPE_G_ARRAY_OF_UINT          (dbus_g_type_get_collection ("GArray", G_TYPE_UINT))
#define DBUS_TYPE_G_ARRAY_OF_ARRAY_OF_UINT (dbus_g_type_get_collection ("GPtrArray", DBUS_TYPE_G_ARRAY_OF_UINT))
#define DBUS_TYPE_G_MAP_OF_VARIANT         (dbus_g_type_get_map ("GHashTable", G_TYPE_STRING, G_TYPE_VALUE))
#define DBUS_TYPE_G_IP6_ROUTE              (dbus_g_type_get_struct ("GValueArray", DBUS_TYPE_G_UCHAR_ARRAY, G_TYPE_UINT, DBUS_TYPE_G_UCHAR_ARRAY, G_TYPE_UINT, G_TYPE_INVALID))
#define DBUS_TYPE_G_ARRAY_OF_IP6_ROUTE     (dbus_g_type_get_collection ("GPtrArray", DBUS_TYPE_G_IP6_ROUTE))

static void
helper_failed (DBusGConnection *connection, const char *reason)
{
	DBusGProxy *proxy;
	GError *err = NULL;

	g_warning ("nm-nopenconnect-service-openconnect-helper did not receive a valid %s from openconnect", reason);

	proxy = dbus_g_proxy_new_for_name (connection,
	                                   NM_DBUS_SERVICE_OPENCONNECT,
	                                   NM_VPN_DBUS_PLUGIN_PATH,
	                                   NM_VPN_DBUS_PLUGIN_INTERFACE);

	dbus_g_proxy_call (proxy, "SetFailure", &err,
	                   G_TYPE_STRING, reason,
	                   G_TYPE_INVALID,
	                   G_TYPE_INVALID);

	if (err) {
		g_warning ("Could not send failure information: %s", err->message);
		g_error_free (err);
	}

	g_object_unref (proxy);

	exit (1);
}

static void
send_config (DBusGConnection *connection, GHashTable *config,
             GHashTable *ip4config, GHashTable *ip6config)
{
	DBusGProxy *proxy;
	GError *err = NULL;

	proxy = dbus_g_proxy_new_for_name (connection,
	                                   NM_DBUS_SERVICE_OPENCONNECT,
	                                   NM_VPN_DBUS_PLUGIN_PATH,
	                                   NM_VPN_DBUS_PLUGIN_INTERFACE);

	if (!dbus_g_proxy_call (proxy, "SetConfig", &err,
	                        DBUS_TYPE_G_MAP_OF_VARIANT,
	                        config,
	                        G_TYPE_INVALID,
	                        G_TYPE_INVALID))
		goto done;

	if (ip4config) {
		if (!dbus_g_proxy_call (proxy, "SetIp4Config", &err,
		                        DBUS_TYPE_G_MAP_OF_VARIANT,
		                        ip4config,
		                        G_TYPE_INVALID,
		                        G_TYPE_INVALID))
			goto done;
	}

	if (ip6config) {
		if (!dbus_g_proxy_call (proxy, "SetIp6Config", &err,
		                        DBUS_TYPE_G_MAP_OF_VARIANT,
		                        ip6config,
		                        G_TYPE_INVALID,
		                        G_TYPE_INVALID))
			goto done;
	}

 done:
	if (err) {
		g_warning ("Could not send configuration information: %s", err->message);
		g_error_free (err);
	}

	g_object_unref (proxy);
}

static GValue *
str_to_gvalue (const char *str, gboolean try_convert)
{
	GValue *val;

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

	val = g_slice_new0 (GValue);
	g_value_init (val, G_TYPE_STRING);
	g_value_set_string (val, str);

	return val;
}

static GValue *
uint_to_gvalue (guint32 num)
{
	GValue *val;

	if (num == 0)
		return NULL;

	val = g_slice_new0 (GValue);
	g_value_init (val, G_TYPE_UINT);
	g_value_set_uint (val, num);

	return val;
}

static GValue *
bool_to_gvalue (gboolean b)
{
	GValue *val;

	val = g_slice_new0 (GValue);
	g_value_init (val, G_TYPE_BOOLEAN);
	g_value_set_boolean (val, b);
	return val;
}

static GValue *
addr4_to_gvalue (const char *str)
{
	struct in_addr	temp_addr;

	/* Empty */
	if (!str || strlen (str) < 1)
		return NULL;

	if (inet_pton (AF_INET, str, &temp_addr) <= 0)
		return NULL;

	return uint_to_gvalue (temp_addr.s_addr);
}

static GValue *
addr4_list_to_gvalue (const char *str)
{
	GValue *val;
	char **split;
	int i;
	GArray *array;

	/* Empty */
	if (!str || strlen (str) < 1)
		return NULL;

	split = g_strsplit (str, " ", -1);
	if (g_strv_length (split) == 0)
		return NULL;

	array = g_array_sized_new (FALSE, TRUE, sizeof (guint32), g_strv_length (split));
	for (i = 0; split[i]; i++) {
		struct in_addr addr;

		if (inet_pton (AF_INET, split[i], &addr) > 0) {
			g_array_append_val (array, addr.s_addr);
		} else {
			g_strfreev (split);
			g_array_free (array, TRUE);
			return NULL;
		}
	}

	g_strfreev (split);

	val = g_slice_new0 (GValue);
	g_value_init (val, DBUS_TYPE_G_UINT_ARRAY);
	g_value_set_boxed (val, array);

	return val;
}

static GValue *
addr6_to_gvalue (const char *str)
{
	struct in6_addr temp_addr;
	GValue *val;
	GByteArray *ba;

	/* Empty */
	if (!str || strlen (str) < 1)
		return NULL;

	if (inet_pton (AF_INET6, str, &temp_addr) <= 0)
		return NULL;

	val = g_slice_new0 (GValue);
	g_value_init (val, DBUS_TYPE_G_UCHAR_ARRAY);
	ba = g_byte_array_new ();
	g_byte_array_append (ba, (guint8 *) &temp_addr, sizeof (temp_addr));
	g_value_take_boxed (val, ba);
	return val;
}

static GValue *
addr6_list_to_gvalue (const char *str)
{
	GValue *val;
	char **split;
	int i;
	GPtrArray *array;
	GByteArray *ba;

	/* Empty */
	if (!str || strlen (str) < 1)
		return NULL;

	split = g_strsplit (str, " ", -1);
	if (g_strv_length (split) == 0)
		return NULL;

	array = g_ptr_array_new_full (g_strv_length (split),
	                              (GDestroyNotify) g_byte_array_unref);
	for (i = 0; split[i]; i++) {
		struct in6_addr addr;

		if (inet_pton (AF_INET6, split[i], &addr) > 0) {
			ba = g_byte_array_new ();
			g_byte_array_append (ba, (guint8 *) &addr, sizeof (addr));
			g_ptr_array_add (array, ba);
		} else {
			g_strfreev (split);
			g_ptr_array_free (array, TRUE);
			return NULL;
		}
	}

	g_strfreev (split);

	val = g_slice_new0 (GValue);
	g_value_init (val, DBUS_TYPE_G_ARRAY_OF_ARRAY_OF_UINT);
	g_value_set_boxed (val, array);

	return val;
}

#define BUFLEN 256

static GValue *
split_dns_list_to_gvalue (const char *str)
{
	GValue *val;
	char **split;

	if (!str || strlen (str) < 1)
		return NULL;

	split = g_strsplit (str, ",", -1);
	if (g_strv_length (split) == 0)
		return NULL;

	val = g_slice_new0 (GValue);
	g_value_init (val, G_TYPE_STRV);
	g_value_take_boxed (val, split);

	return val;
}

static GValue *
get_ip4_routes (void)
{
	GValue *value = NULL;
	GPtrArray *routes;
	char *tmp;
	int num;
	int i;

	tmp = getenv ("CISCO_SPLIT_INC");
	if (!tmp || strlen (tmp) < 1)
		return NULL;

	num = atoi (tmp);
	if (!num)
		return NULL;

	routes = g_ptr_array_new ();

	for (i = 0; i < num; i++) {
		GArray *array;
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

		array = g_array_sized_new (FALSE, TRUE, sizeof (guint32), 4);
		g_array_append_val (array, network.s_addr);
		g_array_append_val (array, prefix);
		g_array_append_val (array, next_hop);
		g_array_append_val (array, metric);
		g_ptr_array_add (routes, array);
	}

	if (routes->len > 0) {
		value = g_new0 (GValue, 1);
		g_value_init (value, DBUS_TYPE_G_ARRAY_OF_ARRAY_OF_UINT);
		g_value_take_boxed (value, routes);
	} else
		g_ptr_array_free (routes, TRUE);

	return value;
}

/* Taken from libnm-util; will be gone and replaced with a call to
 * nm_utils_ip_routes_to_variant with port to GDBus. */
static void
nm_utils_ip6_routes_to_gvalue (GSList *list, GValue *value)
{
	GPtrArray *routes;
	GSList *iter;

	routes = g_ptr_array_new ();

	for (iter = list; iter; iter = iter->next) {
		NMIPRoute *route = (NMIPRoute *) iter->data;
		GValueArray *array;
		const struct in6_addr *addr;
		GByteArray *ba;
		GValue element = G_VALUE_INIT;

		array = g_value_array_new (4);

		g_value_init (&element, DBUS_TYPE_G_UCHAR_ARRAY);
		if (inet_pton (AF_INET6, nm_ip_route_get_dest (route), &addr) <= 0) {
			g_warning ("Bad route destination: '%s", nm_ip_route_get_dest (route));
			continue;
		}
		ba = g_byte_array_new ();
		g_byte_array_append (ba, (guchar *)addr, sizeof (*addr));
		g_value_take_boxed (&element, ba);
		g_value_array_append (array, &element);
		g_value_unset (&element);

		g_value_init (&element, G_TYPE_UINT);
		g_value_set_uint (&element, nm_ip_route_get_prefix (route));
		g_value_array_append (array, &element);
		g_value_unset (&element);

		g_value_init (&element, DBUS_TYPE_G_UCHAR_ARRAY);
		if (inet_pton (AF_INET6, nm_ip_route_get_next_hop (route), &addr) <= 0) {
			g_warning ("Bad gateway: '%s", nm_ip_route_get_next_hop (route));
			continue;
		}
		ba = g_byte_array_new ();
		g_byte_array_append (ba, (guchar *)addr, sizeof (*addr));
		g_value_take_boxed (&element, ba);
		g_value_array_append (array, &element);
		g_value_unset (&element);

		g_value_init (&element, G_TYPE_UINT);
		g_value_set_uint (&element, nm_ip_route_get_metric (route));
		g_value_array_append (array, &element);
		g_value_unset (&element);

		g_ptr_array_add (routes, array);
	}

	g_value_take_boxed (value, routes);
}

static GValue *
get_ip6_routes (void)
{
	GValue *value = NULL;
	GSList *routes;
	char *tmp;
	int num;
	int i;

	tmp = getenv ("CISCO_IPV6_SPLIT_INC");
	if (!tmp || strlen (tmp) < 1)
		return NULL;

	num = atoi (tmp);
	if (!num)
		return NULL;

	routes = NULL;

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

		routes = g_slist_append (routes, route);
	}

	if (routes) {
		GSList *iter;

		value = g_slice_new0 (GValue);
		g_value_init (value, DBUS_TYPE_G_ARRAY_OF_IP6_ROUTE);
		nm_utils_ip6_routes_to_gvalue (routes, value);

		for (iter = routes; iter; iter = iter->next)
			nm_ip_route_unref (iter->data);
		g_slist_free (routes);
	}

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
	DBusGConnection *connection;
	char *tmp;
	GHashTable *config, *ip4config, *ip6config;
	GValue *val;
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

	connection = dbus_g_bus_get (DBUS_BUS_SYSTEM, &err);
	if (!connection) {
		g_warning ("Could not get the system bus: %s", err->message);
		exit (1);
	}

	config = g_hash_table_new (g_str_hash, g_str_equal);
	ip4config = g_hash_table_new (g_str_hash, g_str_equal);
	ip6config = g_hash_table_new (g_str_hash, g_str_equal);

	/* Gateway */
	val = addr4_to_gvalue (getenv ("VPNGATEWAY"));
	if (!val)
		val = addr6_to_gvalue (getenv ("VPNGATEWAY"));
	if (val)
		g_hash_table_insert (config, NM_VPN_PLUGIN_CONFIG_EXT_GATEWAY, val);
	else
		helper_failed (connection, "VPN Gateway");

	/* Tunnel device */
	val = str_to_gvalue (getenv ("TUNDEV"), FALSE);
	if (val)
		g_hash_table_insert (config, NM_VPN_PLUGIN_CONFIG_TUNDEV, val);
	else
		helper_failed (connection, "Tunnel Device");

	/* Banner */
	val = str_to_gvalue (getenv ("CISCO_BANNER"), TRUE);
	if (val)
		g_hash_table_insert (config, NM_VPN_PLUGIN_CONFIG_BANNER, val);

	/* Default domain */
	val = str_to_gvalue (getenv ("CISCO_DEF_DOMAIN"), TRUE);
	if (val)
		g_hash_table_insert (ip4config, NM_VPN_PLUGIN_IP4_CONFIG_DOMAIN, val);

	/* MTU  */
	tmp = getenv ("INTERNAL_IP4_MTU");
	if (tmp && strlen (tmp)) {
		long int mtu;

		errno = 0;
		mtu = strtol (tmp, NULL, 10);
		if (errno || mtu < 0 || mtu > 20000) {
			g_warning ("Ignoring invalid tunnel MTU '%s'", tmp);
		} else {
			val = uint_to_gvalue ((guint32) mtu);
			g_hash_table_insert (config, NM_VPN_PLUGIN_CONFIG_MTU, val);
		}
	}

	/* IPv4 address */
	val = addr4_to_gvalue (getenv ("INTERNAL_IP4_ADDRESS"));
	if (val)
		g_hash_table_insert (ip4config, NM_VPN_PLUGIN_IP4_CONFIG_ADDRESS, val);
	else
		helper_failed (connection, "IP4 Address");

	/* IPv4 PTP address; for openconnect PTP address == internal IPv4 address */
	val = addr4_to_gvalue (getenv ("INTERNAL_IP4_ADDRESS"));
	if (val)
		g_hash_table_insert (ip4config, NM_VPN_PLUGIN_IP4_CONFIG_PTP, val);
	else
		helper_failed (connection, "IP4 PTP Address");

	/* IPv4 Netmask */
	tmp = getenv ("INTERNAL_IP4_NETMASK");
	if (tmp && inet_pton (AF_INET, tmp, &temp_addr) > 0) {
		val = uint_to_gvalue (nm_utils_ip4_netmask_to_prefix (temp_addr.s_addr));
		g_hash_table_insert (ip4config, NM_VPN_PLUGIN_IP4_CONFIG_PREFIX, val);
	}

	/* DNS */
	val = addr4_list_to_gvalue (getenv ("INTERNAL_IP4_DNS"));
	if (val)
		g_hash_table_insert (ip4config, NM_VPN_PLUGIN_IP4_CONFIG_DNS, val);

	/* WINS servers */
	val = addr4_list_to_gvalue (getenv ("INTERNAL_IP4_NBNS"));
	if (val)
		g_hash_table_insert (ip4config, NM_VPN_PLUGIN_IP4_CONFIG_NBNS, val);

	/* Split DNS domains */
	val = split_dns_list_to_gvalue (getenv ("CISCO_SPLIT_DNS"));
	if (val)
		g_hash_table_insert (config, NM_VPN_PLUGIN_IP4_CONFIG_DOMAINS, val);

	/* Routes */
	val = get_ip4_routes ();
	if (val) {
		g_hash_table_insert (ip4config, NM_VPN_PLUGIN_IP4_CONFIG_ROUTES, val);
		/* If routes-to-include were provided, that means no default route */
		g_hash_table_insert (ip4config, NM_VPN_PLUGIN_IP4_CONFIG_NEVER_DEFAULT,
		                     bool_to_gvalue (TRUE));
	}

	/* IPv6 address */
	tmp = getenv ("INTERNAL_IP6_ADDRESS");
	if (tmp && strlen (tmp)) {
		val = addr6_to_gvalue (tmp);
		if (val)
			g_hash_table_insert (ip6config, NM_VPN_PLUGIN_IP6_CONFIG_ADDRESS, val);
		else
			helper_failed (connection, "IP6 Address");
	}

	/* IPv6 PTP address; for openconnect PTP address == internal IPv6 address */
	tmp = getenv ("INTERNAL_IP6_ADDRESS");
	if (tmp && strlen (tmp)) {
		val = addr6_to_gvalue (tmp);
		if (val)
			g_hash_table_insert (ip6config, NM_VPN_PLUGIN_IP6_CONFIG_PTP, val);
		else
			helper_failed (connection, "IP6 PTP Address");
	}

	/* IPv6 Netmask */
	tmp = getenv ("INTERNAL_IP6_NETMASK");
	if (tmp)
		tmp = strchr (tmp, '/');
	if (tmp) {
		val = uint_to_gvalue (strtol (tmp + 1, NULL, 10));
		g_hash_table_insert (ip6config, NM_VPN_PLUGIN_IP6_CONFIG_PREFIX, val);
	}

	/* DNS */
	val = addr6_list_to_gvalue (getenv ("INTERNAL_IP6_DNS"));
	if (val)
		g_hash_table_insert (ip6config, NM_VPN_PLUGIN_IP6_CONFIG_DNS, val);

	/* Routes */
	val = get_ip6_routes ();
	if (val) {
		g_hash_table_insert (ip6config, NM_VPN_PLUGIN_IP6_CONFIG_ROUTES, val);
		/* If routes-to-include were provided, that means no default route */
		g_hash_table_insert (ip6config, NM_VPN_PLUGIN_IP6_CONFIG_NEVER_DEFAULT,
		                     bool_to_gvalue (TRUE));
	}

	if (g_hash_table_size (ip4config)) {
		g_hash_table_insert (config, NM_VPN_PLUGIN_CONFIG_HAS_IP4,
		                     bool_to_gvalue (TRUE));
	} else {
		g_hash_table_destroy (ip4config);
		ip4config = NULL;
	}

	if (g_hash_table_size (ip6config)) {
		g_hash_table_insert (config, NM_VPN_PLUGIN_CONFIG_HAS_IP6,
		                     bool_to_gvalue (TRUE));
	} else {
		g_hash_table_destroy (ip6config);
		ip6config = NULL;
	}

	/* Send the config info to nm-openconnect-service */
	send_config (connection, config, ip4config, ip6config);

	exit (0);
}
