/* -*- Mode: C; tab-width: 5; indent-tabs-mode: t; c-basic-offset: 5 -*- */
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
 * Based on nm-openconnect-vpnc.h:
 *   Copyright © 2005 - 2008 Red Hat, Inc.
 *   Copyright © 2007 - 2008 Novell, Inc.
 */

#ifndef NM_OPENCONNECT_PLUGIN_H
#define NM_OPENCONNECT_PLUGIN_H

#include <glib.h>
#include <NetworkManager.h>
#include <nm-vpn-service-plugin.h>

#include "nm-openconnect-service-defines.h"

#define NM_TYPE_OPENCONNECT_PLUGIN            (nm_openconnect_plugin_get_type ())
#define NM_OPENCONNECT_PLUGIN(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_OPENCONNECT_PLUGIN, NMOpenconnectPlugin))
#define NM_OPENCONNECT_PLUGIN_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_OPENCONNECT_PLUGIN, NMOpenconnectPluginClass))
#define NM_IS_OPENCONNECT_PLUGIN(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_OPENCONNECT_PLUGIN))
#define NM_IS_OPENCONNECT_PLUGIN_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_OPENCONNECT_PLUGIN))
#define NM_OPENCONNECT_PLUGIN_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_OPENCONNECT_PLUGIN, NMOpenconnectPluginClass))

typedef struct {
	NMVpnServicePlugin parent;
} NMOpenconnectPlugin;

typedef struct {
	NMVpnServicePluginClass parent;
} NMOpenconnectPluginClass;

GType nm_openconnect_plugin_get_type (void);

NMOpenconnectPlugin *nm_openconnect_plugin_new (void);

#define NM_OPENCONNECT_USER "nm-openconnect"

#endif /* NM_OPENCONNECT_PLUGIN_H */
