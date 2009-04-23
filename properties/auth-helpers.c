/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/***************************************************************************
 *
 * Copyright (C) 2008 Dan Williams, <dcbw@redhat.com>
 * Copyright (C) 2008 Tambet Ingo, <tambet@gmail.com>
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

#include <string.h>
#include <sys/types.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#include <glib/gi18n-lib.h>

#include "auth-helpers.h"
#include "nm-openconnect.h"
#include "../src/nm-openconnect-service.h"

void
tls_pw_init_auth_widget (GladeXML *xml,
                         GtkSizeGroup *group,
                         NMSettingVPN *s_vpn,
                         const char *contype,
                         const char *prefix,
                         ChangedCallback changed_cb,
                         gpointer user_data)
{
	GtkWidget *widget;
	const char *value;
	char *tmp;
	GtkFileFilter *filter;

	g_return_if_fail (xml != NULL);
	g_return_if_fail (group != NULL);
	g_return_if_fail (changed_cb != NULL);
	g_return_if_fail (prefix != NULL);

	tmp = g_strdup_printf ("%s_ca_cert_chooser", prefix);
	widget = glade_xml_get_widget (xml, tmp);
	g_free (tmp);

	gtk_size_group_add_widget (group, widget);
	filter = tls_file_chooser_filter_new ();
	gtk_file_chooser_add_filter (GTK_FILE_CHOOSER (widget), filter);
	gtk_file_chooser_set_local_only (GTK_FILE_CHOOSER (widget), TRUE);
	gtk_file_chooser_button_set_title (GTK_FILE_CHOOSER_BUTTON (widget),
	                                   _("Choose a Certificate Authority certificate..."));
	g_signal_connect (G_OBJECT (widget), "selection-changed", G_CALLBACK (changed_cb), user_data);

	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENCONNECT_KEY_CACERT);
		if (value && strlen (value))
			gtk_file_chooser_set_filename (GTK_FILE_CHOOSER (widget), value);
	}

	if (!strcmp (contype, NM_OPENCONNECT_AUTHTYPE_CERT) ||
		!strcmp (contype, NM_OPENCONNECT_AUTHTYPE_CERT_TPM)) {
		tmp = g_strdup_printf ("%s_user_cert_chooser", prefix);
		widget = glade_xml_get_widget (xml, tmp);
		g_free (tmp);

		gtk_size_group_add_widget (group, widget);
		filter = tls_file_chooser_filter_new ();
		gtk_file_chooser_add_filter (GTK_FILE_CHOOSER (widget), filter);
		gtk_file_chooser_set_local_only (GTK_FILE_CHOOSER (widget), TRUE);
		gtk_file_chooser_button_set_title (GTK_FILE_CHOOSER_BUTTON (widget),
		                                   _("Choose your personal certificate..."));
		g_signal_connect (G_OBJECT (widget), "selection-changed", G_CALLBACK (changed_cb), user_data);

		if (s_vpn) {
			value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENCONNECT_KEY_USERCERT);
			if (value && strlen (value))
				gtk_file_chooser_set_filename (GTK_FILE_CHOOSER (widget), value);
		}

		tmp = g_strdup_printf ("%s_private_key_chooser", prefix);
		widget = glade_xml_get_widget (xml, tmp);
		g_free (tmp);

		gtk_size_group_add_widget (group, widget);
		filter = tls_file_chooser_filter_new ();
		gtk_file_chooser_add_filter (GTK_FILE_CHOOSER (widget), filter);
		gtk_file_chooser_set_local_only (GTK_FILE_CHOOSER (widget), TRUE);
		gtk_file_chooser_button_set_title (GTK_FILE_CHOOSER_BUTTON (widget),
		                                   _("Choose your private key..."));
		g_signal_connect (G_OBJECT (widget), "selection-changed", G_CALLBACK (changed_cb), user_data);

		if (s_vpn) {
			value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENCONNECT_KEY_PRIVKEY);
			if (value && strlen (value))
				gtk_file_chooser_set_filename (GTK_FILE_CHOOSER (widget), value);
		}
	}

	if (!strcmp (contype, NM_OPENCONNECT_AUTHTYPE_PASSWORD)) {
		tmp = g_strdup_printf ("%s_username_entry", prefix);
		widget = glade_xml_get_widget (xml, tmp);
		g_free (tmp);

		gtk_size_group_add_widget (group, widget);
		if (s_vpn) {
			value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENCONNECT_KEY_USERNAME);
			if (value && strlen (value))
				gtk_entry_set_text (GTK_ENTRY (widget), value);
		}
		g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (changed_cb), user_data);
	}
}

static gboolean
validate_file_chooser (GladeXML *xml, const char *name)
{
	GtkWidget *widget;
	char *str;

	widget = glade_xml_get_widget (xml, name);
	str = gtk_file_chooser_get_filename (GTK_FILE_CHOOSER (widget));
	if (!str || !strlen (str))
		return FALSE;
	return TRUE;
}

static gboolean
validate_tls (GladeXML *xml, const char *prefix, GError **error)
{
	char *tmp;
	gboolean valid;

#if 0 // optional
	tmp = g_strdup_printf ("%s_ca_cert_chooser", prefix);
	valid = validate_file_chooser (xml, tmp);
	g_free (tmp);
	if (!valid) {
		g_set_error (error,
		             OPENCONNECT_PLUGIN_UI_ERROR,
		             OPENCONNECT_PLUGIN_UI_ERROR_INVALID_PROPERTY,
		             NM_OPENCONNECT_KEY_CACERT);
		return FALSE;
	}
#endif
	tmp = g_strdup_printf ("%s_user_cert_chooser", prefix);
	valid = validate_file_chooser (xml, tmp);
	g_free (tmp);
	if (!valid) {
		g_set_error (error,
		             OPENCONNECT_PLUGIN_UI_ERROR,
		             OPENCONNECT_PLUGIN_UI_ERROR_INVALID_PROPERTY,
		             NM_OPENCONNECT_KEY_USERCERT);
		return FALSE;
	}
#if 0 // also optional -- can be in the cert 
	tmp = g_strdup_printf ("%s_private_key_chooser", prefix);
	valid = validate_file_chooser (xml, tmp);
	g_free (tmp);
	if (!valid) {
		g_set_error (error,
		             OPENCONNECT_PLUGIN_UI_ERROR,
		             OPENCONNECT_PLUGIN_UI_ERROR_INVALID_PROPERTY,
		             NM_OPENCONNECT_KEY_PRIVKEY);
		return FALSE;
	}
#endif
	return TRUE;
}

gboolean
auth_widget_check_validity (GladeXML *xml, const char *contype, GError **error)
{
#if 0
	GtkWidget *widget;
	const char *str;
#endif

	if (!strcmp (contype, NM_OPENCONNECT_AUTHTYPE_CERT) ||
		!strcmp (contype, NM_OPENCONNECT_AUTHTYPE_CERT_TPM)) {
		if (!validate_tls (xml, "cert", error))
			return FALSE;
	} else if (!strcmp (contype, NM_OPENCONNECT_AUTHTYPE_PASSWORD)) {
#if 0 // optional
		if (!validate_file_chooser (xml, "pw_ca_cert_chooser")) {
			g_set_error (error,
			             OPENCONNECT_PLUGIN_UI_ERROR,
			             OPENCONNECT_PLUGIN_UI_ERROR_INVALID_PROPERTY,
			             NM_OPENCONNECT_KEY_CACERT);
			return FALSE;
		}
// as is this... the auth-dialog can ask for it.
		widget = glade_xml_get_widget (xml, "pw_username_entry");
		str = gtk_entry_get_text (GTK_ENTRY (widget));
		if (!str || !strlen (str)) {
			g_set_error (error,
			             OPENCONNECT_PLUGIN_UI_ERROR,
			             OPENCONNECT_PLUGIN_UI_ERROR_INVALID_PROPERTY,
			             NM_OPENCONNECT_KEY_USERNAME);
			return FALSE;
		}
#endif
	} else
		g_assert_not_reached ();

	return TRUE;
}

static void
update_from_filechooser (GladeXML *xml,
                         const char *key,
                         const char *prefix,
                         const char *widget_name,
                         NMSettingVPN *s_vpn)
{
	GtkWidget *widget;
	char *tmp, *filename;

	g_return_if_fail (xml != NULL);
	g_return_if_fail (key != NULL);
	g_return_if_fail (prefix != NULL);
	g_return_if_fail (widget_name != NULL);
	g_return_if_fail (s_vpn != NULL);

	tmp = g_strdup_printf ("%s_%s", prefix, widget_name);
	widget = glade_xml_get_widget (xml, tmp);
	g_free (tmp);

	filename = gtk_file_chooser_get_filename (GTK_FILE_CHOOSER (widget));
	if (!filename)
		return;

	if (strlen (filename))
		nm_setting_vpn_add_data_item (s_vpn, key, filename);
	
	g_free (filename);
}

static void
update_tls (GladeXML *xml, const char *prefix, NMSettingVPN *s_vpn)
{
	update_from_filechooser (xml, NM_OPENCONNECT_KEY_CACERT, prefix, "ca_cert_chooser", s_vpn);
	update_from_filechooser (xml, NM_OPENCONNECT_KEY_USERCERT, prefix, "user_cert_chooser", s_vpn);
	update_from_filechooser (xml, NM_OPENCONNECT_KEY_PRIVKEY, prefix, "private_key_chooser", s_vpn);
}

static void
update_username (GladeXML *xml, const char *prefix, NMSettingVPN *s_vpn)
{
	GtkWidget *widget;
	char *tmp;
	const char *str;

	g_return_if_fail (xml != NULL);
	g_return_if_fail (prefix != NULL);
	g_return_if_fail (s_vpn != NULL);

	tmp = g_strdup_printf ("%s_username_entry", prefix);
	widget = glade_xml_get_widget (xml, tmp);
	g_free (tmp);

	str = gtk_entry_get_text (GTK_ENTRY (widget));
	if (str && strlen (str))
		nm_setting_vpn_add_data_item (s_vpn, NM_OPENCONNECT_KEY_USERNAME, str);
}

gboolean
auth_widget_update_connection (GladeXML *xml,
                               const char *contype,
                               NMSettingVPN *s_vpn)
{
	if (!strcmp (contype, NM_OPENCONNECT_AUTHTYPE_CERT) ||
		!strcmp (contype, NM_OPENCONNECT_AUTHTYPE_CERT_TPM)) {
		update_tls (xml, "cert", s_vpn);
	} else if (!strcmp (contype, NM_OPENCONNECT_AUTHTYPE_PASSWORD)) {
		update_from_filechooser (xml, NM_OPENCONNECT_KEY_CACERT, "pw",
								 "ca_cert_chooser", s_vpn);
		update_username (xml, "pw", s_vpn);
	} else
		g_assert_not_reached ();

	return TRUE;
}

static const char *
find_tag (const char *tag, const char *buf, gsize len)
{
	gsize i, taglen;

	taglen = strlen (tag);
	if (len < taglen)
		return NULL;

	for (i = 0; i < len - taglen; i++) {
		if (memcmp (buf + i, tag, taglen) == 0)
			return buf + i;
	}
	return NULL;
}

static const char *pem_rsa_key_begin = "-----BEGIN RSA PRIVATE KEY-----";
static const char *pem_dsa_key_begin = "-----BEGIN DSA PRIVATE KEY-----";
static const char *pem_tss_keyblob_begin = "-----BEGIN TSS KEY BLOB-----";
static const char *pem_cert_begin = "-----BEGIN CERTIFICATE-----";

static gboolean
tls_default_filter (const GtkFileFilterInfo *filter_info, gpointer data)
{
	char *contents = NULL, *p, *ext;
	gsize bytes_read = 0;
	gboolean show = FALSE;
	struct stat statbuf;

	if (!filter_info->filename)
		return FALSE;

	p = strrchr (filter_info->filename, '.');
	if (!p)
		return FALSE;

	ext = g_ascii_strdown (p, -1);
	if (!ext)
		return FALSE;
	if (strcmp (ext, ".pem") && strcmp (ext, ".crt") && strcmp (ext, ".key")) {
		g_free (ext);
		return FALSE;
	}
	g_free (ext);

	/* Ignore files that are really large */
	if (!stat (filter_info->filename, &statbuf)) {
		if (statbuf.st_size > 500000)
			return FALSE;
	}

	if (!g_file_get_contents (filter_info->filename, &contents, &bytes_read, NULL))
		return FALSE;

	if (bytes_read < 400)  /* needs to be lower? */
		goto out;

	/* Check for PEM signatures */
	if (find_tag (pem_rsa_key_begin, (const char *) contents, bytes_read)) {
		show = TRUE;
		goto out;
	}

	if (find_tag (pem_dsa_key_begin, (const char *) contents, bytes_read)) {
		show = TRUE;
		goto out;
	}

	if (find_tag (pem_tss_keyblob_begin, (const char *) contents, bytes_read)) {
		show = TRUE;
		goto out;
	}

	if (find_tag (pem_cert_begin, (const char *) contents, bytes_read)) {
		show = TRUE;
		goto out;
	}

out:
	g_free (contents);
	return show;
}

GtkFileFilter *
tls_file_chooser_filter_new (void)
{
	GtkFileFilter *filter;

	filter = gtk_file_filter_new ();
	gtk_file_filter_add_custom (filter, GTK_FILE_FILTER_FILENAME, tls_default_filter, NULL, NULL);
	gtk_file_filter_set_name (filter, _("PEM certificates (*.pem, *.crt, *.key)"));
	return filter;
}

