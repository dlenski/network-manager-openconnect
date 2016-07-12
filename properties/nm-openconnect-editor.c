/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/***************************************************************************
 * Copyright (C) 2005 David Zeuthen, <davidz@redhat.com>
 * Copyright (C) 2005 - 2008 Dan Williams, <dcbw@redhat.com>
 * Copyright (C) 2005 - 2011 Red Hat, Inc.
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

#include "nm-default.h"

#include "nm-openconnect-editor.h"

#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <gtk/gtk.h>

#include <openconnect.h>

#ifndef OPENCONNECT_CHECK_VER
#define OPENCONNECT_CHECK_VER(x,y) 0
#endif

#if !OPENCONNECT_CHECK_VER(2,1)
#define openconnect_has_stoken_support() 0
#endif
#if !OPENCONNECT_CHECK_VER(2,2)
#define openconnect_has_oath_support() 0
#endif
#if !OPENCONNECT_CHECK_VER(5,0)
#define openconnect_has_yubioath_support() 0
#endif

#include "auth-helpers.h"

/************** UI widget class **************/

static void openconnect_editor_interface_init (NMVpnEditorInterface *iface_class);

G_DEFINE_TYPE_EXTENDED (OpenconnectEditor, openconnect_editor, G_TYPE_OBJECT, 0,
                        G_IMPLEMENT_INTERFACE (NM_TYPE_VPN_EDITOR,
                                               openconnect_editor_interface_init))

#define OPENCONNECT_EDITOR_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), OPENCONNECT_TYPE_EDITOR, OpenconnectEditorPrivate))

typedef struct {
	GtkBuilder *builder;
	GtkWidget *widget;
	GtkSizeGroup *group;
	GtkWindowGroup *window_group;
	gboolean window_added;
} OpenconnectEditorPrivate;

#define COL_AUTH_NAME 0
#define COL_AUTH_PAGE 1
#define COL_AUTH_TYPE 2

/*****************************************************************************/

static gboolean
check_validity (OpenconnectEditor *self, GError **error)
{
	OpenconnectEditorPrivate *priv = OPENCONNECT_EDITOR_GET_PRIVATE (self);
	GtkWidget *widget;
	const char *str;

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "gateway_entry"));
	str = gtk_entry_get_text (GTK_ENTRY (widget));
	if (!str || !strlen (str)) {
		g_set_error (error,
		             NMV_EDITOR_PLUGIN_ERROR,
		             NMV_EDITOR_PLUGIN_ERROR_INVALID_PROPERTY,
		             NM_OPENCONNECT_KEY_GATEWAY);
		return FALSE;
	}


	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "proxy_entry"));
	str = gtk_entry_get_text (GTK_ENTRY (widget));
	if (str && str[0] &&
		strncmp(str, "socks://", 8) && strncmp(str, "http://", 7)) {
		g_set_error (error,
		             NMV_EDITOR_PLUGIN_ERROR,
		             NMV_EDITOR_PLUGIN_ERROR_INVALID_PROPERTY,
		             NM_OPENCONNECT_KEY_PROXY);
		return FALSE;
	}

	if (!auth_widget_check_validity (priv->builder, error))
		return FALSE;

	return TRUE;
}

static void
stuff_changed_cb (GtkWidget *widget, gpointer user_data)
{
	g_signal_emit_by_name (OPENCONNECT_EDITOR (user_data), "changed");
}

static gboolean
init_token_mode_options (GtkComboBox *token_mode)
{
	GtkListStore *token_mode_list = GTK_LIST_STORE (gtk_combo_box_get_model (token_mode));
	GtkTreeModel *model = GTK_TREE_MODEL (token_mode_list);
	GtkTreeIter iter;
	gboolean iter_valid;
	int valid_rows = 0;

	if (!gtk_tree_model_get_iter_first (model, &iter))
		return FALSE;
	do {
		char *token_type;

		gtk_tree_model_get (model, &iter, 2, &token_type, -1);
		if (!strcmp (token_type, "stoken") && !openconnect_has_stoken_support ())
			iter_valid = gtk_list_store_remove (token_mode_list, &iter);
		else if (!strcmp (token_type, "totp") && !openconnect_has_oath_support ())
			iter_valid = gtk_list_store_remove (token_mode_list, &iter);
		else if (!strcmp (token_type, "hotp") &&
				 (!openconnect_has_oath_support () || !OPENCONNECT_CHECK_VER(3,4)))
			iter_valid = gtk_list_store_remove (token_mode_list, &iter);
		else if (!strcmp (token_type, "yubioath") && !openconnect_has_yubioath_support ())
			iter_valid = gtk_list_store_remove (token_mode_list, &iter);
		else {
			iter_valid = gtk_tree_model_iter_next (model, &iter);
			valid_rows++;
		}
		g_free (token_type);
	} while (iter_valid);

	/* if the only option is "Disabled", don't show the token section at all */
	return valid_rows > 1;
}

static gboolean
init_token_ui (OpenconnectEditor *self,
               OpenconnectEditorPrivate *priv,
               NMSettingVpn *s_vpn)
{
	GtkWidget *widget;
	GtkComboBox *token_mode;
	GtkTextBuffer *buffer;
	const char *value;

	token_mode = GTK_COMBO_BOX (gtk_builder_get_object (priv->builder, "token_mode"));
	if (!token_mode)
		return FALSE;
	if (!init_token_mode_options (token_mode))
		return TRUE;

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "token_vbox"));
	if (!widget)
		return FALSE;
	gtk_box_pack_start (GTK_BOX (priv->widget), widget, FALSE, FALSE, 0);

	if (s_vpn) {
		GtkTreeModel *model = gtk_combo_box_get_model (token_mode);
		int active_option = 0;

		value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENCONNECT_KEY_TOKEN_MODE);
		if (value) {
			int i;
			GtkTreeIter iter;

			if (!gtk_tree_model_get_iter_first (model, &iter))
				return FALSE;
			for (i = 0; ; i++) {
				char *pref_value;

				gtk_tree_model_get (model, &iter, 1, &pref_value, -1);
				if (!strcmp (value, pref_value))
					active_option = i;
				g_free (pref_value);
				if (!gtk_tree_model_iter_next (model, &iter))
					break;
			}
		}
		gtk_combo_box_set_active (token_mode, active_option);
	}
	g_signal_connect (G_OBJECT (token_mode), "changed", G_CALLBACK (stuff_changed_cb), self);

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "token_secret"));
	if (!widget)
		return FALSE;
	buffer = gtk_text_view_get_buffer (GTK_TEXT_VIEW (widget));
	if (!buffer)
		return FALSE;
	if (s_vpn) {
		value = nm_setting_vpn_get_secret (s_vpn, NM_OPENCONNECT_KEY_TOKEN_SECRET);
		if (!value)
			value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENCONNECT_KEY_TOKEN_SECRET);
		if (value)
			gtk_text_buffer_set_text (buffer, value, -1);
	}
	g_signal_connect (G_OBJECT (buffer), "changed", G_CALLBACK (stuff_changed_cb), self);

	return TRUE;
}

static gboolean
init_protocol_combo_options (GtkComboBox *protocol_combo)
{
#if OPENCONNECT_CHECK_VER(5,1)
	GtkListStore *protocol_combo_list = GTK_LIST_STORE (gtk_combo_box_get_model (protocol_combo));
	GtkTreeIter iter;

	gtk_list_store_append(protocol_combo_list, &iter);
	gtk_list_store_set(protocol_combo_list, &iter,
					   0, _("Juniper/Pulse Network Connect"),
					   1, "nc",
					   -1);
	return TRUE;
#else
	return FALSE;
#endif
}

static gboolean
init_protocol_ui (OpenconnectEditor *self,
				  OpenconnectEditorPrivate *priv,
				  NMSettingVpn *s_vpn)
{
	GtkComboBox *protocol_combo;
	const char *value;

	protocol_combo = GTK_COMBO_BOX (gtk_builder_get_object (priv->builder, "protocol_combo"));
	if (!protocol_combo)
		return FALSE;
	if (!init_protocol_combo_options (protocol_combo))
		return TRUE;

#if 0
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "token_vbox"));
	if (!widget)
		return FALSE;
	gtk_box_pack_start (GTK_BOX (priv->widget), widget, FALSE, FALSE, 0);
#endif

	if (s_vpn) {
		GtkTreeModel *model = gtk_combo_box_get_model (protocol_combo);
		int active_option = 0;

		value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENCONNECT_KEY_PROTOCOL);
		if (value) {
			int i;
			GtkTreeIter iter;

			if (!gtk_tree_model_get_iter_first (model, &iter))
				return FALSE;
			for (i = 0; ; i++) {
				char *pref_value;

				gtk_tree_model_get (model, &iter, 1, &pref_value, -1);
				if (!strcmp (value, pref_value))
					active_option = i;
				g_free (pref_value);
				if (!gtk_tree_model_iter_next (model, &iter))
					break;
			}
		}
		gtk_combo_box_set_active (protocol_combo, active_option);
	}
	g_signal_connect (G_OBJECT (protocol_combo), "changed", G_CALLBACK (stuff_changed_cb), self);

	return TRUE;
}

static gboolean
init_editor_plugin (OpenconnectEditor *self, NMConnection *connection, GError **error)
{
	OpenconnectEditorPrivate *priv = OPENCONNECT_EDITOR_GET_PRIVATE (self);
	NMSettingVpn *s_vpn;
	GtkWidget *widget;
	const char *value;

	s_vpn = nm_connection_get_setting_vpn (connection);

	priv->group = gtk_size_group_new (GTK_SIZE_GROUP_HORIZONTAL);

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "gateway_entry"));
	if (!widget)
		return FALSE;
	gtk_size_group_add_widget (priv->group, widget);
	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENCONNECT_KEY_GATEWAY);
		if (value)
			gtk_entry_set_text (GTK_ENTRY (widget), value);
	}
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (stuff_changed_cb), self);

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "proxy_entry"));
	if (!widget)
		return FALSE;
	gtk_size_group_add_widget (priv->group, widget);
	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENCONNECT_KEY_PROXY);
		if (value)
			gtk_entry_set_text (GTK_ENTRY (widget), value);
	}
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (stuff_changed_cb), self);

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "fsid_button"));
	if (!widget)
		return FALSE;
	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENCONNECT_KEY_PEM_PASSPHRASE_FSID);
		if (value && !strcmp(value, "yes"))
			gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON (widget), TRUE);
	}
	g_signal_connect (G_OBJECT (widget), "toggled", G_CALLBACK (stuff_changed_cb), self);

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "csd_button"));
	if (!widget)
		return FALSE;
	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENCONNECT_KEY_CSD_ENABLE);
		if (value && !strcmp(value, "yes"))
			gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON (widget), TRUE);
	}
	g_signal_connect (G_OBJECT (widget), "toggled", G_CALLBACK (stuff_changed_cb), self);

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "csd_wrapper_entry"));
	if (!widget)
		return FALSE;
	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENCONNECT_KEY_CSD_WRAPPER);
		if (value)
			gtk_entry_set_text (GTK_ENTRY (widget), value);
	}
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (stuff_changed_cb), self);

	if (init_token_ui (self, priv, s_vpn) == FALSE)
		return FALSE;

	if (init_protocol_ui (self, priv, s_vpn) == FALSE)
		return FALSE;

	tls_pw_init_auth_widget (priv->builder, priv->group, s_vpn, stuff_changed_cb, self);

	return TRUE;
}

static GObject *
get_widget (NMVpnEditor *iface)
{
	OpenconnectEditor *self = OPENCONNECT_EDITOR (iface);
	OpenconnectEditorPrivate *priv = OPENCONNECT_EDITOR_GET_PRIVATE (self);

	return G_OBJECT (priv->widget);
}

static gboolean
update_connection (NMVpnEditor *iface,
                   NMConnection *connection,
                   GError **error)
{
	OpenconnectEditor *self = OPENCONNECT_EDITOR (iface);
	OpenconnectEditorPrivate *priv = OPENCONNECT_EDITOR_GET_PRIVATE (self);
	NMSettingVpn *s_vpn;
	GtkWidget *widget;
	char *str;
	GtkTreeModel *model;
	GtkTreeIter iter;
	gboolean token_secret_editable = FALSE;
	GtkTextIter iter_start, iter_end;
	GtkTextBuffer *buffer;
	const char *auth_type = NULL;
	const char *protocol = NULL;

	s_vpn = nm_connection_get_setting_vpn (connection);
	if (s_vpn)
		protocol = nm_setting_vpn_get_data_item (s_vpn, NM_OPENCONNECT_KEY_PROTOCOL);

	s_vpn = NM_SETTING_VPN (nm_setting_vpn_new ());
	g_object_set (s_vpn, NM_SETTING_VPN_SERVICE_TYPE, NM_VPN_SERVICE_TYPE_OPENCONNECT, NULL);

	if (protocol)
		nm_setting_vpn_add_data_item (s_vpn, NM_OPENCONNECT_KEY_PROTOCOL, protocol);

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "protocol_combo"));
	model = gtk_combo_box_get_model (GTK_COMBO_BOX (widget));
	if (gtk_combo_box_get_active_iter (GTK_COMBO_BOX (widget), &iter)) {
		gtk_tree_model_get (model, &iter, 1, &str, -1);
		nm_setting_vpn_add_data_item (s_vpn, NM_OPENCONNECT_KEY_PROTOCOL, str);
		g_free(str);
	}

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "gateway_entry"));
	str = (char *) gtk_entry_get_text (GTK_ENTRY (widget));
	if (str && strlen (str))
		nm_setting_vpn_add_data_item (s_vpn, NM_OPENCONNECT_KEY_GATEWAY, str);

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "proxy_entry"));
	str = (char *) gtk_entry_get_text (GTK_ENTRY (widget));
	if (str && strlen (str))
		nm_setting_vpn_add_data_item (s_vpn, NM_OPENCONNECT_KEY_PROXY, str);

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "fsid_button"));
	str = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (widget))?"yes":"no";
	nm_setting_vpn_add_data_item (s_vpn, NM_OPENCONNECT_KEY_PEM_PASSPHRASE_FSID, str);

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "csd_button"));
	str = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (widget))?"yes":"no";
	nm_setting_vpn_add_data_item (s_vpn, NM_OPENCONNECT_KEY_CSD_ENABLE, str);

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "csd_wrapper_entry"));
	str = (char *) gtk_entry_get_text (GTK_ENTRY (widget));
	if (str && strlen (str))
		nm_setting_vpn_add_data_item (s_vpn, NM_OPENCONNECT_KEY_CSD_WRAPPER, str);

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "token_mode"));
	model = gtk_combo_box_get_model (GTK_COMBO_BOX (widget));
	if (gtk_combo_box_get_active_iter (GTK_COMBO_BOX (widget), &iter)) {
		gtk_tree_model_get (model, &iter, 1, &str, 3, &token_secret_editable, -1);
		nm_setting_vpn_add_data_item (s_vpn, NM_OPENCONNECT_KEY_TOKEN_MODE, str);
		g_free(str);
	}

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "token_secret_label"));
	gtk_widget_set_sensitive (widget, token_secret_editable);

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "token_secret"));
	gtk_widget_set_sensitive (widget, token_secret_editable);

	buffer = gtk_text_view_get_buffer (GTK_TEXT_VIEW (widget));
	gtk_text_buffer_get_start_iter (buffer, &iter_start);
	gtk_text_buffer_get_end_iter (buffer, &iter_end);
	str = (char *) gtk_text_buffer_get_text (buffer, &iter_start, &iter_end, TRUE);
	if (str) {
		char *src = str, *dst = str;

		/* zap invalid characters */
		for (; *src; src++)
			if (*src >= ' ' && *src <= '~')
				*(dst++) = *src;
		*dst = 0;

		if (strlen (str))
			nm_setting_vpn_add_secret (s_vpn, NM_OPENCONNECT_KEY_TOKEN_SECRET, str);
	}

	if (!check_validity (self, error))
		return FALSE;

	/* These are different for every login session, and should not be stored */
	nm_setting_set_secret_flags (NM_SETTING (s_vpn), "gwcert",
	                             NM_SETTING_SECRET_FLAG_NOT_SAVED, NULL);
	nm_setting_set_secret_flags (NM_SETTING (s_vpn), "cookie",
	                             NM_SETTING_SECRET_FLAG_NOT_SAVED, NULL);
	nm_setting_set_secret_flags (NM_SETTING (s_vpn), "gateway",
	                             NM_SETTING_SECRET_FLAG_NOT_SAVED, NULL);

	/* These are purely internal data for the auth-dialog, and should be stored */
	nm_setting_set_secret_flags (NM_SETTING (s_vpn), "xmlconfig",
	                             NM_SETTING_SECRET_FLAG_NONE, NULL);
	nm_setting_set_secret_flags (NM_SETTING (s_vpn), "lasthost",
	                             NM_SETTING_SECRET_FLAG_NONE, NULL);
	nm_setting_set_secret_flags (NM_SETTING (s_vpn), "autoconnect",
	                             NM_SETTING_SECRET_FLAG_NONE, NULL);
	nm_setting_set_secret_flags (NM_SETTING (s_vpn), "certsigs",
	                             NM_SETTING_SECRET_FLAG_NONE, NULL);
	/* Note that the auth-dialog will also store "extra" secrets for form
	   entries, depending on the arbitrary forms that we're offered by the
	   server during authentication. We can't know about those in advance,
	   but the presence of the above four is sufficient to trigger a write
	   of the new secrets, and the code in the keyfile plugin will treat the
	   absence of a flags configuration for a given secret as equivalent to
	   FLAG_NONE, and thus save our "extra" secrets too. */

	auth_widget_update_connection (priv->builder, auth_type, s_vpn);

	nm_connection_add_setting (connection, NM_SETTING (s_vpn));
	return TRUE;
}

NMVpnEditor *
nm_vpn_editor_new (NMConnection *connection, GError **error)
{
	NMVpnEditor *object;
	OpenconnectEditorPrivate *priv;
	char *ui_file;

	if (error)
		g_return_val_if_fail (*error == NULL, NULL);

	object = g_object_new (OPENCONNECT_TYPE_EDITOR, NULL);
	if (!object) {
		g_set_error (error, NMV_EDITOR_PLUGIN_ERROR, 0, "could not create openconnect object");
		return NULL;
	}

	priv = OPENCONNECT_EDITOR_GET_PRIVATE (object);

	ui_file = g_strdup_printf ("%s/%s", UIDIR, "nm-openconnect-dialog.ui");
	priv->builder = gtk_builder_new ();

	gtk_builder_set_translation_domain (priv->builder, GETTEXT_PACKAGE);

	if (!gtk_builder_add_from_file (priv->builder, ui_file, error)) {
		g_warning ("Couldn't load builder file: %s",
		           error && *error ? (*error)->message : "(unknown)");
		g_clear_error (error);
		g_set_error (error, NMV_EDITOR_PLUGIN_ERROR, 0,
		             "could not load required resources at %s", ui_file);
		g_free (ui_file);
		g_object_unref (object);
		return NULL;
	}
	g_free (ui_file);

	priv->widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "openconnect-vbox"));
	if (!priv->widget) {
		g_set_error (error, NMV_EDITOR_PLUGIN_ERROR, 0, "could not load UI widget");
		g_object_unref (object);
		return NULL;
	}
	g_object_ref_sink (priv->widget);

	priv->window_group = gtk_window_group_new ();

	if (!init_editor_plugin (OPENCONNECT_EDITOR (object), connection, error)) {
		g_object_unref (object);
		return NULL;
	}

	return object;
}

static void
dispose (GObject *object)
{
	OpenconnectEditor *plugin = OPENCONNECT_EDITOR (object);
	OpenconnectEditorPrivate *priv = OPENCONNECT_EDITOR_GET_PRIVATE (plugin);

	if (priv->group)
		g_object_unref (priv->group);

	if (priv->window_group)
		g_object_unref (priv->window_group);

	if (priv->widget)
		g_object_unref (priv->widget);

	if (priv->builder)
		g_object_unref (priv->builder);

	G_OBJECT_CLASS (openconnect_editor_parent_class)->dispose (object);
}

static void
openconnect_editor_class_init (OpenconnectEditorClass *req_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (req_class);

	g_type_class_add_private (req_class, sizeof (OpenconnectEditorPrivate));

	object_class->dispose = dispose;
}

static void
openconnect_editor_init (OpenconnectEditor *plugin)
{
}

static void
openconnect_editor_interface_init (NMVpnEditorInterface *iface_class)
{
	/* interface implementation */
	iface_class->get_widget = get_widget;
	iface_class->update_connection = update_connection;
}

/*****************************************************************************/

#ifndef NM_VPN_OLD

#include "nm-openconnect-editor-plugin.h"

G_MODULE_EXPORT NMVpnEditor *
nm_vpn_editor_factory_openconnect (NMVpnEditorPlugin *editor_plugin,
                                   NMConnection *connection,
                                   GError **error)
{
	g_return_val_if_fail (!error || !*error, NULL);

	return nm_vpn_editor_new (connection, error);
}
#endif

