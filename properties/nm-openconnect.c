/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/***************************************************************************
 * CVSID: $Id$
 *
 * nm-openconnect.c : GNOME UI dialogs for configuring openconnect VPN connections
 *
 * Copyright (C) 2005 David Zeuthen, <davidz@redhat.com>
 * Copyright (C) 2005 - 2008 Dan Williams, <dcbw@redhat.com>
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
 **************************************************************************/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
#include <glib/gi18n-lib.h>
#include <string.h>
#include <gtk/gtk.h>
#include <glade/glade.h>

#define NM_VPN_API_SUBJECT_TO_CHANGE

#include <nm-vpn-plugin-ui-interface.h>
#include <nm-setting-vpn.h>
#include <nm-setting-connection.h>
#include <nm-setting-ip4-config.h>

#include "../src/nm-openconnect-service.h"
#include "nm-openconnect.h"
#include "auth-helpers.h"

#define OPENCONNECT_PLUGIN_NAME    _("Cisco AnyConnect Compatible VPN (openconnect)")
#define OPENCONNECT_PLUGIN_DESC    _("Compatible with Cisco AnyConnect SSL VPN.")
#define OPENCONNECT_PLUGIN_SERVICE NM_DBUS_SERVICE_OPENCONNECT 


/************** plugin class **************/

static void openconnect_plugin_ui_interface_init (NMVpnPluginUiInterface *iface_class);

G_DEFINE_TYPE_EXTENDED (OpenconnectPluginUi, openconnect_plugin_ui, G_TYPE_OBJECT, 0,
						G_IMPLEMENT_INTERFACE (NM_TYPE_VPN_PLUGIN_UI_INTERFACE,
											   openconnect_plugin_ui_interface_init))

/************** UI widget class **************/

static void openconnect_plugin_ui_widget_interface_init (NMVpnPluginUiWidgetInterface *iface_class);

G_DEFINE_TYPE_EXTENDED (OpenconnectPluginUiWidget, openconnect_plugin_ui_widget, G_TYPE_OBJECT, 0,
						G_IMPLEMENT_INTERFACE (NM_TYPE_VPN_PLUGIN_UI_WIDGET_INTERFACE,
											   openconnect_plugin_ui_widget_interface_init))

#define OPENCONNECT_PLUGIN_UI_WIDGET_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), OPENCONNECT_TYPE_PLUGIN_UI_WIDGET, OpenconnectPluginUiWidgetPrivate))

typedef struct {
	GladeXML *xml;
	GtkWidget *widget;
	GtkSizeGroup *group;
	GtkWindowGroup *window_group;
	gboolean window_added;
} OpenconnectPluginUiWidgetPrivate;

#define COL_AUTH_NAME 0
#define COL_AUTH_PAGE 1
#define COL_AUTH_TYPE 2

GQuark
openconnect_plugin_ui_error_quark (void)
{
	static GQuark error_quark = 0;

	if (G_UNLIKELY (error_quark == 0))
		error_quark = g_quark_from_static_string ("openconnect-plugin-ui-error-quark");

	return error_quark;
}

/* This should really be standard. */
#define ENUM_ENTRY(NAME, DESC) { NAME, "" #NAME "", DESC }

GType
openconnect_plugin_ui_error_get_type (void)
{
	static GType etype = 0;

	if (etype == 0) {
		static const GEnumValue values[] = {
			/* Unknown error. */
			ENUM_ENTRY (OPENCONNECT_PLUGIN_UI_ERROR_UNKNOWN, "UnknownError"),
			/* The specified property was invalid. */
			ENUM_ENTRY (OPENCONNECT_PLUGIN_UI_ERROR_INVALID_PROPERTY, "InvalidProperty"),
			/* The specified property was missing and is required. */
			ENUM_ENTRY (OPENCONNECT_PLUGIN_UI_ERROR_MISSING_PROPERTY, "MissingProperty"),
			{ 0, 0, 0 }
		};
		etype = g_enum_register_static ("OpenconnectPluginUiError", values);
	}
	return etype;
}

static gboolean
check_validity (OpenconnectPluginUiWidget *self, GError **error)
{
	OpenconnectPluginUiWidgetPrivate *priv = OPENCONNECT_PLUGIN_UI_WIDGET_GET_PRIVATE (self);
	GtkWidget *widget;
	const char *str;
	GtkTreeModel *model;
	GtkTreeIter iter;
	const char *contype = NULL;

	widget = glade_xml_get_widget (priv->xml, "gateway_entry");
	str = gtk_entry_get_text (GTK_ENTRY (widget));
	if (!str || !strlen (str)) {
		g_set_error (error,
		             OPENCONNECT_PLUGIN_UI_ERROR,
		             OPENCONNECT_PLUGIN_UI_ERROR_INVALID_PROPERTY,
		             NM_OPENCONNECT_KEY_GATEWAY);
		return FALSE;
	}

	widget = glade_xml_get_widget (priv->xml, "auth_combo");
	model = gtk_combo_box_get_model (GTK_COMBO_BOX (widget));
	g_assert (model);
	g_assert (gtk_combo_box_get_active_iter (GTK_COMBO_BOX (widget), &iter));

	gtk_tree_model_get (model, &iter, COL_AUTH_TYPE, &contype, -1);
	if (!auth_widget_check_validity (priv->xml, contype, error))
		return FALSE;

	return TRUE;
}

static void
stuff_changed_cb (GtkWidget *widget, gpointer user_data)
{
	g_signal_emit_by_name (OPENCONNECT_PLUGIN_UI_WIDGET (user_data), "changed");
}

static void
auth_combo_changed_cb (GtkWidget *combo, gpointer user_data)
{
	OpenconnectPluginUiWidget *self = OPENCONNECT_PLUGIN_UI_WIDGET (user_data);
	OpenconnectPluginUiWidgetPrivate *priv = OPENCONNECT_PLUGIN_UI_WIDGET_GET_PRIVATE (self);
	GtkWidget *auth_notebook;
	GtkTreeModel *model;
	GtkTreeIter iter;
	gint new_page = 0;

	auth_notebook = glade_xml_get_widget (priv->xml, "auth_notebook");
	g_assert (auth_notebook);

	model = gtk_combo_box_get_model (GTK_COMBO_BOX (combo));
	g_assert (model);
	g_assert (gtk_combo_box_get_active_iter (GTK_COMBO_BOX (combo), &iter));

	gtk_tree_model_get (model, &iter, COL_AUTH_PAGE, &new_page, -1);
	gtk_notebook_set_current_page (GTK_NOTEBOOK (auth_notebook), new_page);

	stuff_changed_cb (combo, self);
}

static gboolean
init_plugin_ui (OpenconnectPluginUiWidget *self, NMConnection *connection, GError **error)
{
	OpenconnectPluginUiWidgetPrivate *priv = OPENCONNECT_PLUGIN_UI_WIDGET_GET_PRIVATE (self);
	NMSettingVPN *s_vpn;
	GtkWidget *widget;
	GtkListStore *store;
	GtkTreeIter iter;
	int active = -1;
	const char *value;
	const char *contype = NM_OPENCONNECT_AUTHTYPE_PASSWORD;

	s_vpn = (NMSettingVPN *) nm_connection_get_setting (connection, NM_TYPE_SETTING_VPN);

	priv->group = gtk_size_group_new (GTK_SIZE_GROUP_HORIZONTAL);

	widget = glade_xml_get_widget (priv->xml, "gateway_entry");
	if (!widget)
		return FALSE;
	gtk_size_group_add_widget (priv->group, widget);
	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENCONNECT_KEY_GATEWAY);
		if (value)
			gtk_entry_set_text (GTK_ENTRY (widget), value);
	}
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (stuff_changed_cb), self);

	widget = glade_xml_get_widget (priv->xml, "auth_combo");
	if (!widget)
		return FALSE;
	gtk_size_group_add_widget (priv->group, widget);

	store = gtk_list_store_new (3, G_TYPE_STRING, G_TYPE_INT, G_TYPE_STRING);

	if (s_vpn) {
		contype = nm_setting_vpn_get_data_item (s_vpn, NM_OPENCONNECT_KEY_AUTHTYPE);
		if (contype) {
			if (   strcmp (contype, NM_OPENCONNECT_AUTHTYPE_CERT)
			    && strcmp (contype, NM_OPENCONNECT_AUTHTYPE_CERT_TPM)
			    && strcmp (contype, NM_OPENCONNECT_AUTHTYPE_PASSWORD))
				contype = NM_OPENCONNECT_AUTHTYPE_PASSWORD;
		} else
			contype = NM_OPENCONNECT_AUTHTYPE_PASSWORD;
	}

	/* SecurID/password auth widget */
	tls_pw_init_auth_widget (priv->xml, priv->group, s_vpn,
							 NM_OPENCONNECT_AUTHTYPE_PASSWORD, "pw",
							 stuff_changed_cb, self);

	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter,
	                    COL_AUTH_NAME, _("Password / SecurID"),
	                    COL_AUTH_PAGE, 1,
	                    COL_AUTH_TYPE, NM_OPENCONNECT_AUTHTYPE_PASSWORD,
	                    -1);

	/* Certificate auth widget */
	tls_pw_init_auth_widget (priv->xml, priv->group, s_vpn,
							 NM_OPENCONNECT_AUTHTYPE_CERT, "cert",
							 stuff_changed_cb, self);

	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter,
	                    COL_AUTH_NAME, _("Certificate (TLS)"),
	                    COL_AUTH_PAGE, 0,
	                    COL_AUTH_TYPE, NM_OPENCONNECT_AUTHTYPE_CERT,
	                    -1);
	if ((active < 0) && !strcmp (contype, NM_OPENCONNECT_AUTHTYPE_CERT))
		active = 1;

	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter,
	                    COL_AUTH_NAME, _("Certificate (TLS) with TPM"),
	                    COL_AUTH_PAGE, 0,
	                    COL_AUTH_TYPE, NM_OPENCONNECT_AUTHTYPE_CERT_TPM,
	                    -1);
	if ((active < 0) && !strcmp (contype, NM_OPENCONNECT_AUTHTYPE_CERT_TPM))
		active = 2;

	gtk_combo_box_set_model (GTK_COMBO_BOX (widget), GTK_TREE_MODEL (store));
	g_object_unref (store);
	g_signal_connect (widget, "changed", G_CALLBACK (auth_combo_changed_cb), self);
	gtk_combo_box_set_active (GTK_COMBO_BOX (widget), active < 0 ? 0 : active);

	return TRUE;
}

static GObject *
get_widget (NMVpnPluginUiWidgetInterface *iface)
{
	OpenconnectPluginUiWidget *self = OPENCONNECT_PLUGIN_UI_WIDGET (iface);
	OpenconnectPluginUiWidgetPrivate *priv = OPENCONNECT_PLUGIN_UI_WIDGET_GET_PRIVATE (self);

	return G_OBJECT (priv->widget);
}

static gboolean
update_connection (NMVpnPluginUiWidgetInterface *iface,
                   NMConnection *connection,
                   GError **error)
{
	OpenconnectPluginUiWidget *self = OPENCONNECT_PLUGIN_UI_WIDGET (iface);
	OpenconnectPluginUiWidgetPrivate *priv = OPENCONNECT_PLUGIN_UI_WIDGET_GET_PRIVATE (self);
	NMSettingVPN *s_vpn;
	GtkWidget *widget;
	char *str;
	GtkTreeModel *model;
	GtkTreeIter iter;
	const char *auth_type = NULL;

	if (!check_validity (self, error))
		return FALSE;

	s_vpn = NM_SETTING_VPN (nm_setting_vpn_new ());
	g_object_set (s_vpn, NM_SETTING_VPN_SERVICE_TYPE, NM_DBUS_SERVICE_OPENCONNECT, NULL);

	/* Gateway */
	widget = glade_xml_get_widget (priv->xml, "gateway_entry");
	str = (char *) gtk_entry_get_text (GTK_ENTRY (widget));
	if (str && strlen (str))
		nm_setting_vpn_add_data_item (s_vpn, NM_OPENCONNECT_KEY_GATEWAY, str);

	widget = glade_xml_get_widget (priv->xml, "auth_combo");
	model = gtk_combo_box_get_model (GTK_COMBO_BOX (widget));
	if (gtk_combo_box_get_active_iter (GTK_COMBO_BOX (widget), &iter)) {
		gtk_tree_model_get (model, &iter, COL_AUTH_TYPE, &auth_type, -1);
		nm_setting_vpn_add_data_item (s_vpn, NM_OPENCONNECT_KEY_AUTHTYPE, auth_type);
		auth_widget_update_connection (priv->xml, auth_type, s_vpn);
	}

	nm_connection_add_setting (connection, NM_SETTING (s_vpn));
	return TRUE;
}

static gboolean
save_secrets (NMVpnPluginUiWidgetInterface *iface,
              NMConnection *connection,
              GError **error)
{
	return TRUE;
}


static NMVpnPluginUiWidgetInterface *
nm_vpn_plugin_ui_widget_interface_new (NMConnection *connection, GError **error)
{
	NMVpnPluginUiWidgetInterface *object;
	OpenconnectPluginUiWidgetPrivate *priv;
	char *glade_file;

	if (error)
		g_return_val_if_fail (*error == NULL, NULL);

	object = NM_VPN_PLUGIN_UI_WIDGET_INTERFACE (g_object_new (OPENCONNECT_TYPE_PLUGIN_UI_WIDGET, NULL));
	if (!object) {
		g_set_error (error, OPENCONNECT_PLUGIN_UI_ERROR, 0, "could not create openconnect object");
		return NULL;
	}

	priv = OPENCONNECT_PLUGIN_UI_WIDGET_GET_PRIVATE (object);

	glade_file = g_strdup_printf ("%s/%s", GLADEDIR, "nm-openconnect-dialog.glade");
	priv->xml = glade_xml_new (glade_file, "openconnect-vbox", GETTEXT_PACKAGE);
	if (priv->xml == NULL) {
		g_set_error (error, OPENCONNECT_PLUGIN_UI_ERROR, 0,
		             "could not load required resources at %s", glade_file);
		g_free (glade_file);
		g_object_unref (object);
		return NULL;
	}
	g_free (glade_file);

	priv->widget = glade_xml_get_widget (priv->xml, "openconnect-vbox");
	if (!priv->widget) {
		g_set_error (error, OPENCONNECT_PLUGIN_UI_ERROR, 0, "could not load UI widget");
		g_object_unref (object);
		return NULL;
	}
	g_object_ref_sink (priv->widget);

	priv->window_group = gtk_window_group_new ();

	if (!init_plugin_ui (OPENCONNECT_PLUGIN_UI_WIDGET (object), connection, error)) {
		g_object_unref (object);
		return NULL;
	}

	return object;
}

static void
dispose (GObject *object)
{
	OpenconnectPluginUiWidget *plugin = OPENCONNECT_PLUGIN_UI_WIDGET (object);
	OpenconnectPluginUiWidgetPrivate *priv = OPENCONNECT_PLUGIN_UI_WIDGET_GET_PRIVATE (plugin);

	if (priv->group)
		g_object_unref (priv->group);

	if (priv->window_group)
		g_object_unref (priv->window_group);

	if (priv->widget)
		g_object_unref (priv->widget);

	if (priv->xml)
		g_object_unref (priv->xml);

	G_OBJECT_CLASS (openconnect_plugin_ui_widget_parent_class)->dispose (object);
}

static void
openconnect_plugin_ui_widget_class_init (OpenconnectPluginUiWidgetClass *req_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (req_class);

	g_type_class_add_private (req_class, sizeof (OpenconnectPluginUiWidgetPrivate));

	object_class->dispose = dispose;
}

static void
openconnect_plugin_ui_widget_init (OpenconnectPluginUiWidget *plugin)
{
}

static void
openconnect_plugin_ui_widget_interface_init (NMVpnPluginUiWidgetInterface *iface_class)
{
	/* interface implementation */
	iface_class->get_widget = get_widget;
	iface_class->update_connection = update_connection;
	iface_class->save_secrets = save_secrets;
}

static gboolean
delete_connection (NMVpnPluginUiInterface *iface,
                   NMConnection *connection,
                   GError **error)
{
	return TRUE;
}

static guint32
get_capabilities (NMVpnPluginUiInterface *iface)
{
	return 0;
}

static NMVpnPluginUiWidgetInterface *
ui_factory (NMVpnPluginUiInterface *iface, NMConnection *connection, GError **error)
{
	return nm_vpn_plugin_ui_widget_interface_new (connection, error);
}

static void
get_property (GObject *object, guint prop_id,
			  GValue *value, GParamSpec *pspec)
{
	switch (prop_id) {
	case NM_VPN_PLUGIN_UI_INTERFACE_PROP_NAME:
		g_value_set_string (value, OPENCONNECT_PLUGIN_NAME);
		break;
	case NM_VPN_PLUGIN_UI_INTERFACE_PROP_DESC:
		g_value_set_string (value, OPENCONNECT_PLUGIN_DESC);
		break;
	case NM_VPN_PLUGIN_UI_INTERFACE_PROP_SERVICE:
		g_value_set_string (value, OPENCONNECT_PLUGIN_SERVICE);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
openconnect_plugin_ui_class_init (OpenconnectPluginUiClass *req_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (req_class);

	object_class->get_property = get_property;

	g_object_class_override_property (object_class,
									  NM_VPN_PLUGIN_UI_INTERFACE_PROP_NAME,
									  NM_VPN_PLUGIN_UI_INTERFACE_NAME);

	g_object_class_override_property (object_class,
									  NM_VPN_PLUGIN_UI_INTERFACE_PROP_DESC,
									  NM_VPN_PLUGIN_UI_INTERFACE_DESC);

	g_object_class_override_property (object_class,
									  NM_VPN_PLUGIN_UI_INTERFACE_PROP_SERVICE,
									  NM_VPN_PLUGIN_UI_INTERFACE_SERVICE);
}

static void
openconnect_plugin_ui_init (OpenconnectPluginUi *plugin)
{
}

static void
openconnect_plugin_ui_interface_init (NMVpnPluginUiInterface *iface_class)
{
	/* interface implementation */
	iface_class->ui_factory = ui_factory;
	iface_class->get_capabilities = get_capabilities;
	iface_class->delete_connection = delete_connection;
}

G_MODULE_EXPORT NMVpnPluginUiInterface *
nm_vpn_plugin_ui_factory (GError **error)
{
	if (error)
		g_return_val_if_fail (*error == NULL, NULL);

	return NM_VPN_PLUGIN_UI_INTERFACE (g_object_new (OPENCONNECT_TYPE_PLUGIN_UI, NULL));
}

