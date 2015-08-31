/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/***************************************************************************
 *
 * Copyright (C) 2008 Dan Williams, <dcbw@redhat.com>
 * Copyright (C) 2008 - 2011 Red Hat, Inc.
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
#include "../src/nm-openconnect-service-defines.h"

void
tls_pw_init_auth_widget (GtkBuilder *builder,
                         GtkSizeGroup *group,
                         NMSettingVpn *s_vpn,
                         ChangedCallback changed_cb,
                         gpointer user_data)
{
	GtkWidget *widget;
	const char *value;
	GtkFileFilter *filter;

	g_return_if_fail (builder != NULL);
	g_return_if_fail (group != NULL);
	g_return_if_fail (changed_cb != NULL);

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "ca_cert_chooser"));

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

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "cert_user_cert_chooser"));

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

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "cert_private_key_chooser"));

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

gboolean
auth_widget_check_validity (GtkBuilder *builder, GError **error)
{
	return TRUE;
}

static void
update_from_filechooser (GtkBuilder *builder,
                         const char *key,
                         const char *widget_name,
                         NMSettingVpn *s_vpn)
{
	GtkWidget *widget;
	char *filename;
	char *authtype;

	g_return_if_fail (builder != NULL);
	g_return_if_fail (key != NULL);
	g_return_if_fail (widget_name != NULL);
	g_return_if_fail (s_vpn != NULL);

	widget = GTK_WIDGET (gtk_builder_get_object (builder, widget_name));

	filename = gtk_file_chooser_get_filename (GTK_FILE_CHOOSER (widget));
	if (filename && strlen(filename)) {
		nm_setting_vpn_add_data_item (s_vpn, key, filename);
		authtype = "cert";
	} else {
		nm_setting_vpn_remove_data_item (s_vpn, key);
		authtype = "password";
	}
	/* Hack to keep older nm-auth-dialog working */
	if (!strcmp(key, NM_OPENCONNECT_KEY_USERCERT))
		nm_setting_vpn_add_data_item (s_vpn, NM_OPENCONNECT_KEY_AUTHTYPE, authtype);
	g_free (filename);
}

gboolean
auth_widget_update_connection (GtkBuilder *builder,
                               const char *contype,
                               NMSettingVpn *s_vpn)
{
	update_from_filechooser (builder, NM_OPENCONNECT_KEY_CACERT, "ca_cert_chooser", s_vpn);
	update_from_filechooser (builder, NM_OPENCONNECT_KEY_USERCERT, "cert_user_cert_chooser", s_vpn);
	update_from_filechooser (builder, NM_OPENCONNECT_KEY_PRIVKEY, "cert_private_key_chooser", s_vpn);
	return TRUE;
}

static const char *
find_tag (const char *tag, const char *buf, gsize len)
{
	gsize i, taglen;

	taglen = strlen (tag);
	if (len < taglen)
		return NULL;

	for (i = 0; i < len - taglen + 1; i++) {
		if (memcmp (buf + i, tag, taglen) == 0)
			return buf + i;
	}
	return NULL;
}

static const char *pem_rsa_key_begin = "-----BEGIN RSA PRIVATE KEY-----";
static const char *pem_dsa_key_begin = "-----BEGIN DSA PRIVATE KEY-----";
static const char *pem_key_begin = "-----BEGIN PRIVATE KEY-----";
static const char *pem_enc_key_begin = "-----BEGIN ENCRYPTED PRIVATE KEY-----";
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

	if (find_tag (pem_key_begin, (const char *) contents, bytes_read)) {
		show = TRUE;
		goto out;
	}

	if (find_tag (pem_enc_key_begin, (const char *) contents, bytes_read)) {
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

