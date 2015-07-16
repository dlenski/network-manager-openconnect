/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * Copyright © 2008-2012 Intel Corporation.
 *
 * Authors: Jussi Kukkonen <jku@linux.intel.com>
 *          David Woodhouse <dwmw2@infradead.org>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * version 2.1, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to:
 *
 *   Free Software Foundation, Inc.
 *   51 Franklin Street, Fifth Floor,
 *   Boston, MA 02110-1301 USA
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>
#include <errno.h>
#include <unistd.h>
#define _GNU_SOURCE
#include <getopt.h>

#include <libxml/parser.h>
#include <libxml/tree.h>

#include <gtk/gtk.h>
#include <glib/gi18n.h>
#include <glib-unix.h>

#include <nm-vpn-plugin-utils.h>

#define SECRET_API_SUBJECT_TO_CHANGE
#include <libsecret/secret.h>

#include "../src/nm-openconnect-service-defines.h"

#include "openconnect.h"

#if !OPENCONNECT_CHECK_VER(2,1)
#define __openconnect_set_token_mode(...) -EOPNOTSUPP
#elif !OPENCONNECT_CHECK_VER(2,2)
#define __openconnect_set_token_mode(vpninfo, mode, secret) openconnect_set_stoken_mode(vpninfo, 1, secret)
#else
#define __openconnect_set_token_mode openconnect_set_token_mode
#endif

#if OPENCONNECT_CHECK_VER(3,0)
#define NEWGROUP_SUPPORTED		1
#define AUTHGROUP_OPT(form)		(void *)(form)->authgroup_opt
#define AUTHGROUP_SELECTION(form)	(form)->authgroup_selection
#define FORMCHOICE(sopt, i)		((sopt)->choices[i])
#define IGNORE_OPT(opt)			((opt)->flags & OC_FORM_OPT_IGNORE)
#else
#define NEWGROUP_SUPPORTED		0
#define AUTHGROUP_OPT(form)		NULL
#define AUTHGROUP_SELECTION(form)	0
#define FORMCHOICE(sopt, i)		(&(sopt)->choices[i])
#define IGNORE_OPT(opt)			0
#define OC_FORM_RESULT_ERR		-1
#define OC_FORM_RESULT_OK		0
#define OC_FORM_RESULT_CANCELLED	1
#define OC_FORM_RESULT_NEWGROUP		2
#endif

#if OPENCONNECT_CHECK_VER(4,0)
#define dup_option_value(opt)		g_strdup((opt)->_value);
#define OC3DUP(x)			(x)
#define write_config_const		const
#else
#define dup_option_value(opt)		g_strdup((opt)->value);
#define openconnect_set_option_value(opt, val) do { \
		struct oc_form_opt *_o = (opt);				\
		free(_o->value); _o->value = g_strdup(val);		\
	} while (0)
#define openconnect_free_cert_info(v, x) free(x)
#define OC3DUP(x)			g_strdup(x)
#define write_config_const		/* */
#endif

static const SecretSchema openconnect_secret_schema = {
	"org.freedesktop.NetworkManager.Connection.Openconnect",
	SECRET_SCHEMA_DONT_MATCH_NAME,
	{
		{ "vpn_uuid", SECRET_SCHEMA_ATTRIBUTE_STRING },
		{ "auth_id", SECRET_SCHEMA_ATTRIBUTE_STRING },
		{ "label", SECRET_SCHEMA_ATTRIBUTE_STRING },
		{ NULL, 0 },
	}
};

static char *lasthost;

typedef struct vpnhost {
	char *hostname;
	char *hostaddress;
	char *usergroup;
	struct vpnhost *next;
} vpnhost;

vpnhost *vpnhosts;

enum certificate_response{
	CERT_DENIED = -1,
	CERT_USER_NOT_READY,
	CERT_ACCEPTED,
};

/* This struct holds all information we need to add a password to
 * the secret store. It’s used in success_passwords. */
struct keyring_password {
	char *description;
	char *password;
	char *vpn_uuid;
	char *auth_id;
	char *label;
};

static void keyring_password_free(gpointer data);
static void keyring_store_passwords(gpointer key, gpointer value, gpointer user_data);

static void keyring_password_free(gpointer data)
{
	struct keyring_password *kp = (struct keyring_password*)data;
	g_free(kp->description);
	g_free(kp->password);
	g_free(kp->vpn_uuid);
	g_free(kp->auth_id);
	g_free(kp->label);
	g_free(kp);
}

static void keyring_store_passwords(gpointer key, gpointer value, gpointer user_data)
{
	struct keyring_password *kp = (struct keyring_password*)value;

	secret_password_store_sync (&openconnect_secret_schema, NULL,
	                            kp->description, kp->password,
	                            NULL, NULL,
	                            "vpn_uuid", kp->vpn_uuid,
	                            "auth_id", kp->auth_id,
	                            "label", kp->label,
	                            NULL);
}


typedef struct auth_ui_data {
	char *vpn_name;
	char *vpn_uuid;
	GHashTable *options;
	GHashTable *secrets;
	GHashTable *success_secrets;
	GHashTable *success_passwords;
	struct openconnect_info *vpninfo;
	GtkWidget *dialog;
	GtkWidget *combo;
	GtkWidget *connect_button;
	GtkWidget *no_form_label;
	GtkWidget *getting_form_label;
	GtkWidget *ssl_box;
	GtkWidget *cancel_button;
	GtkWidget *login_button;
	GtkWidget *last_notice_icon;
	GtkTextBuffer *log;

	int cookie_retval;

	int cancel_pipes[2];
	gboolean cancelled; /* fully cancel the whole challenge-response series */
	gboolean getting_cookie;

	int form_grabbed;
	GQueue *form_entries; /* modified from worker thread */
	GMutex form_mutex;

	GCond form_retval_changed;
	gpointer form_retval;

	GCond form_shown_changed;
	gboolean form_shown;

	gboolean newgroup;
	gboolean group_set;

	GCond cert_response_changed;
	enum certificate_response cert_response;
} auth_ui_data;

enum {
	AUTH_DIALOG_RESPONSE_LOGIN = 1,
	AUTH_DIALOG_RESPONSE_CANCEL,
} auth_dialog_response;



/* this is here because ssl ui (*opener) does not have a userdata pointer... */
static auth_ui_data *_ui_data;

static void connect_host(auth_ui_data *ui_data);

static void container_child_remove(GtkWidget *widget, gpointer data)
{
	GtkContainer *container = GTK_CONTAINER(data);

	gtk_container_remove(container, widget);
}

static void ssl_box_add_error(auth_ui_data *ui_data, const char *msg)
{
	GtkWidget *hbox, *text, *image;

	hbox = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 8);
	gtk_box_pack_start(GTK_BOX(ui_data->ssl_box), hbox, FALSE, FALSE, 0);

	image = gtk_image_new_from_icon_name("dialog-error",
					     GTK_ICON_SIZE_DIALOG);
	gtk_box_pack_start(GTK_BOX(hbox), image, FALSE, FALSE, 0);

	text = gtk_label_new(msg);
	gtk_label_set_line_wrap(GTK_LABEL(text), TRUE);
	gtk_box_pack_start(GTK_BOX(hbox), text, TRUE, TRUE, 0);
	ui_data->last_notice_icon = NULL;
}

static void ssl_box_add_notice(auth_ui_data *ui_data, const char *msg)
{
	GtkWidget *hbox, *text, *image;

	hbox = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 8);
	gtk_box_pack_start(GTK_BOX(ui_data->ssl_box), hbox, FALSE, FALSE, 0);

	image = gtk_image_new_from_icon_name("dialog-warning",
					     GTK_ICON_SIZE_DIALOG);
	gtk_box_pack_start(GTK_BOX(hbox), image, FALSE, FALSE, 0);

	text = gtk_label_new(msg);
	gtk_label_set_line_wrap(GTK_LABEL(text), TRUE);
	gtk_box_pack_start(GTK_BOX(hbox), text, TRUE, TRUE, 0);
	gtk_widget_show_all(ui_data->ssl_box);
	ui_data->last_notice_icon = image;
}

static void ssl_box_add_info(auth_ui_data *ui_data, const char *msg)
{
	GtkWidget *text;
	int width;

	text = gtk_label_new(msg);
	gtk_label_set_line_wrap(GTK_LABEL(text), TRUE);
	gtk_window_get_size(GTK_WINDOW(ui_data->dialog), &width, NULL);
	/* FIXME: this is not very nice -- can't make the window thinner after this */
	gtk_widget_set_size_request(text, width - 40, -1);
	gtk_box_pack_start(GTK_BOX(ui_data->ssl_box), text, FALSE, FALSE, 0);
}

static void ssl_box_clear(auth_ui_data *ui_data)
{
	gtk_widget_hide(ui_data->no_form_label);
	gtk_widget_hide(ui_data->getting_form_label);
	ui_data->last_notice_icon = NULL;
	gtk_container_foreach(GTK_CONTAINER(ui_data->ssl_box),
			      container_child_remove, ui_data->ssl_box);
	gtk_widget_set_sensitive (ui_data->login_button, FALSE);
	gtk_widget_set_sensitive (ui_data->cancel_button, FALSE);
}

typedef struct ui_fragment_data {
	GtkWidget *widget;
	GtkWidget *entry;
	GCancellable *cancel;
	auth_ui_data *ui_data;
	struct oc_form_opt *opt;
	char *entry_text;
	int initial_selection;
	int grab_focus;
} ui_fragment_data;

static void entry_activate_cb(GtkWidget *widget, auth_ui_data *ui_data)
{
	gtk_dialog_response(GTK_DIALOG(ui_data->dialog), AUTH_DIALOG_RESPONSE_LOGIN);
}

static void evaluate_login_visibility(auth_ui_data *ui_data)
{
	gboolean visible = TRUE;
	gtk_widget_set_sensitive (ui_data->login_button, visible);
}

static void entry_changed(GtkEntry *entry, ui_fragment_data *data)
{
	g_free (data->entry_text);
	data->entry_text = g_strdup(gtk_entry_get_text(entry));
}

static void do_override_label(ui_fragment_data *data, struct oc_choice *choice)
{
	const char *new_label = data->opt->label;

	if (!data->widget)
		return;

	if (choice->override_name && !strcmp(choice->override_name, data->opt->name))
		    new_label = choice->override_label;

	gtk_label_set_text(GTK_LABEL(data->widget), new_label);

}

static gboolean do_newgroup(GtkDialog *dialog)
{
	gtk_dialog_response(dialog, AUTH_DIALOG_RESPONSE_LOGIN);
	return FALSE;
}

static void combo_changed(GtkComboBox *combo, ui_fragment_data *data)
{
	struct oc_form_opt_select *sopt = (void *)data->opt;
	int entry = gtk_combo_box_get_active(combo);
	if (entry < 0)
		return;

	data->entry_text = FORMCHOICE(sopt, entry)->name;

	if (NEWGROUP_SUPPORTED && entry != data->initial_selection) {
		data->ui_data->newgroup = TRUE;
		g_idle_add ((GSourceFunc)do_newgroup, data->ui_data->dialog);
		return;
	}

	g_queue_foreach(data->ui_data->form_entries, (GFunc)do_override_label,
			FORMCHOICE(sopt, entry));
}

static gboolean ui_write_prompt (ui_fragment_data *data)
{
	auth_ui_data *ui_data = _ui_data; /* FIXME global */
	GtkWidget *hbox, *text, *entry;
	int visible;
	const char *label;

	label = data->opt->label;
	visible = (data->opt->type == OC_FORM_OPT_TEXT);

	hbox = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 0);
	gtk_box_pack_start(GTK_BOX(data->ui_data->ssl_box), hbox, FALSE, FALSE, 0);

	text = gtk_label_new(label);
	gtk_box_pack_start(GTK_BOX(hbox), text, FALSE, FALSE, 0);
	data->widget = text;

	entry = gtk_entry_new();
	gtk_box_pack_end(GTK_BOX(hbox), entry, FALSE, FALSE, 0);
	data->entry = entry;
	if (!visible)
		gtk_entry_set_visibility(GTK_ENTRY(entry), FALSE);
	if (data->entry_text)
		gtk_entry_set_text(GTK_ENTRY(entry), data->entry_text);
	/* If it's the first empty one, grab focus. Otherwise, if
	   it's the first item of *any* kind, grab focus but don't
	   admit it (so another empty entry can take focus_ */
	if (!data->entry_text && !data->ui_data->form_grabbed) {
		data->ui_data->form_grabbed = 1;
		gtk_widget_grab_focus (entry);
	} else if (g_queue_peek_tail(ui_data->form_entries) == data)
		gtk_widget_grab_focus (entry);

	g_signal_connect(G_OBJECT(entry), "changed", G_CALLBACK(entry_changed), data);
	g_signal_connect(G_OBJECT(entry), "activate", G_CALLBACK(entry_activate_cb), ui_data);

	/* data is freed in ui_flush in worker thread */

	return FALSE;
}

static gboolean ui_add_select (ui_fragment_data *data)
{
	auth_ui_data *ui_data = _ui_data; /* FIXME global */
	GtkWidget *hbox, *text, *combo;
	struct oc_form_opt_select *sopt = (void *)data->opt;
	int i, user_selection = -1;

	hbox = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 0);
	gtk_box_pack_start(GTK_BOX(data->ui_data->ssl_box), hbox, FALSE, FALSE, 0);

	text = gtk_label_new(data->opt->label);
	gtk_box_pack_start(GTK_BOX(hbox), text, FALSE, FALSE, 0);

	combo = gtk_combo_box_text_new();
	gtk_box_pack_end(GTK_BOX(hbox), combo, FALSE, FALSE, 0);

	for (i = 0; i < sopt->nr_choices; i++) {
		gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(combo), FORMCHOICE(sopt, i)->label);
		if (data->entry_text &&
		    !strcmp(data->entry_text, FORMCHOICE(sopt, i)->name))
			user_selection = i;
	}

	i = data->initial_selection != -1 ? data->initial_selection :
	    user_selection != -1 ? user_selection : 0;
	gtk_combo_box_set_active(GTK_COMBO_BOX(combo), i);
	g_free(data->entry_text);
	data->entry_text = FORMCHOICE(sopt, i)->name;
	data->initial_selection = i;

	if (g_queue_peek_tail(ui_data->form_entries) == data)
		gtk_widget_grab_focus (combo);
	g_signal_connect(G_OBJECT(combo), "changed", G_CALLBACK(combo_changed), data);
	/* Hook up the 'show' signal to ensure that we override prompts on 
	   UI elements which may be coming later. */
	g_signal_connect(G_OBJECT(combo), "show", G_CALLBACK(combo_changed), data);

	/* data is freed in ui_flush in worker thread */

	return FALSE;
}

static gboolean ui_show (auth_ui_data *ui_data)
{
	gtk_widget_hide (ui_data->getting_form_label);
	gtk_widget_show_all (ui_data->ssl_box);
	gtk_widget_set_sensitive (ui_data->cancel_button, TRUE);
	g_mutex_lock (&ui_data->form_mutex);
	evaluate_login_visibility(ui_data);
	ui_data->form_shown = TRUE;
	g_cond_signal (&ui_data->form_shown_changed);
	g_mutex_unlock (&ui_data->form_mutex);

	return FALSE;
}

static char *find_form_answer(GHashTable *secrets, struct oc_auth_form *form,
			      struct oc_form_opt *opt)
{
	char *key, *result;

	key = g_strdup_printf ("form:%s:%s", form->auth_id, opt->name);
	result = g_hash_table_lookup (secrets, key);
	g_free(key);
	return result;
}

/* Callback which is called when we got a reply from the secret store for any
 * password field. Updates the contents of the password field unless the user
 * entered anything in the meantime. */
static void got_keyring_pw(GObject *object, GAsyncResult *result, gpointer userdata)
{
	ui_fragment_data *data = (ui_fragment_data*)userdata;
	GList *list;
	SecretItem *item;
	SecretValue *value = NULL;
	const char *string = NULL;

	list = secret_service_search_finish (SECRET_SERVICE (object), result, NULL);
	if (list != NULL) {
		item = list->data;
		value = secret_item_get_secret (item);
		string = secret_value_get (value, NULL);
	}

	if (string != NULL) {
		if (data->entry) {
			if (!g_ascii_strcasecmp("",
						gtk_entry_get_text(GTK_ENTRY(data->entry)))) {
				gtk_entry_set_text(GTK_ENTRY(data->entry), string);
				if (gtk_widget_has_focus(data->entry))
					gtk_editable_select_region(GTK_EDITABLE(data->entry), 0, -1);
			}
		} else
			data->entry_text = g_strdup (string);
	}

	if (value)
		secret_value_unref (value);
	g_list_free_full (list, g_object_unref);

	/* zero the cancellable so that we don’t attempt to cancel it when
	 * closing the dialog */
	g_clear_object (&data->cancel);
}

/* This part for processing forms from openconnect directly, rather than
   through the SSL UI abstraction (which doesn't allow 'select' options) */

static gboolean ui_form (struct oc_auth_form *form)
{
	auth_ui_data *ui_data = _ui_data; /* FIXME global */
	struct oc_form_opt *opt;

	g_mutex_lock(&ui_data->form_mutex);
	while (!g_queue_is_empty (ui_data->form_entries)) {
		ui_fragment_data *data;
		data = g_queue_pop_tail (ui_data->form_entries);
		g_slice_free (ui_fragment_data, data);
	}
	g_mutex_unlock(&ui_data->form_mutex);

	if (form->banner)
		ssl_box_add_info(ui_data, form->banner);
	if (form->error)
		ssl_box_add_error(ui_data, form->error);
	if (form->message)
		ssl_box_add_info(ui_data, form->message);

	for (opt = form->opts; opt; opt = opt->next) {
		ui_fragment_data *data;

		if (opt->type == OC_FORM_OPT_HIDDEN ||
		    IGNORE_OPT(opt))
			continue;

		data = g_slice_new0 (ui_fragment_data);
		data->ui_data = ui_data;
		data->opt = opt;
		
		if (opt->type == OC_FORM_OPT_PASSWORD ||
		    opt->type == OC_FORM_OPT_TEXT) {
			g_mutex_lock (&ui_data->form_mutex);
			g_queue_push_head(ui_data->form_entries, data);
			g_mutex_unlock (&ui_data->form_mutex);
			if (opt->type != OC_FORM_OPT_PASSWORD) {
				data->entry_text = g_strdup (find_form_answer(ui_data->secrets,
									      form, opt));
				if (!data->entry_text)
					data->entry_text = dup_option_value(opt);
			} else {
				GHashTable *attrs;

				data->cancel = g_cancellable_new ();
				attrs = secret_attributes_build (&openconnect_secret_schema,
				                                 "vpn_uuid", ui_data->vpn_uuid,
				                                 "auth_id", form->auth_id,
				                                 "label", data->opt->name,
				                                 NULL);
				secret_service_search (NULL, &openconnect_secret_schema, attrs,
				                       SECRET_SEARCH_ALL | SECRET_SEARCH_UNLOCK | SECRET_SEARCH_LOAD_SECRETS,
				                       data->cancel, got_keyring_pw, data);
				g_hash_table_unref (attrs);
			}

			ui_write_prompt(data);
		} else if (opt->type == OC_FORM_OPT_SELECT) {
			g_mutex_lock (&ui_data->form_mutex);
			g_queue_push_head(ui_data->form_entries, data);
			g_mutex_unlock (&ui_data->form_mutex);
			data->entry_text = g_strdup (find_form_answer(ui_data->secrets,
								      form, opt));

			if (opt == AUTHGROUP_OPT(form))
				data->initial_selection = AUTHGROUP_SELECTION(form);
			else
				data->initial_selection = -1;

			ui_add_select(data);
		} else
			g_slice_free (ui_fragment_data, data);
	}
	
	return ui_show(ui_data);
}

/* If our stored group_list selection differs from the server default, send a
   NEWGROUP request to try to change it before rendering the form */

static gboolean set_initial_authgroup (auth_ui_data *ui_data, struct oc_auth_form *form)
{
	struct oc_form_opt *opt;

	if (!NEWGROUP_SUPPORTED || ui_data->group_set || !AUTHGROUP_OPT(form))
		return FALSE;
	ui_data->group_set = TRUE;

	for (opt = form->opts; opt; opt = opt->next) {
		int i;
		char *saved_group;
		struct oc_form_opt_select *sopt;

		if (opt != AUTHGROUP_OPT(form))
			continue;

		saved_group = find_form_answer(ui_data->secrets, form, opt);
		if (!saved_group)
			return FALSE;

		sopt = (struct oc_form_opt_select *)opt;
		for (i = 0; i < sopt->nr_choices; i++) {
			struct oc_choice *ch = FORMCHOICE(sopt, i);
			if (!strcmp(saved_group, ch->name) && i != AUTHGROUP_SELECTION(form)) {
				openconnect_set_option_value(opt, saved_group);
				return TRUE;
			}
		}
	}
	return FALSE;
}

static int nm_process_auth_form (void *cbdata, struct oc_auth_form *form)
{
	auth_ui_data *ui_data = cbdata;
	int response;

	if (set_initial_authgroup(ui_data, form))
		return OC_FORM_RESULT_NEWGROUP;

	ui_data->newgroup = FALSE;
	g_idle_add((GSourceFunc)ui_form, form);

	g_mutex_lock(&ui_data->form_mutex);
	/* wait for ui to show */
	while (!ui_data->form_shown) {
		g_cond_wait(&ui_data->form_shown_changed, &ui_data->form_mutex);
	}
	ui_data->form_shown = FALSE;

	if (!ui_data->cancelled) {
		/* wait for form submission or cancel */
		while (!ui_data->form_retval) {
			g_cond_wait(&ui_data->form_retval_changed, &ui_data->form_mutex);
		}
		response = GPOINTER_TO_INT (ui_data->form_retval);
		ui_data->form_retval = NULL;
	} else
		response = AUTH_DIALOG_RESPONSE_CANCEL;

	if (response == AUTH_DIALOG_RESPONSE_LOGIN) {
		/* set entry results and free temporary data structures */
		while (!g_queue_is_empty (ui_data->form_entries)) {
			ui_fragment_data *data;
			data = g_queue_pop_tail (ui_data->form_entries);

			if (data->cancel)
				g_cancellable_cancel(data->cancel);

			if (data->entry_text) {
				openconnect_set_option_value(data->opt, data->entry_text);

				if (data->opt->type == OC_FORM_OPT_TEXT ||
				    data->opt->type == OC_FORM_OPT_SELECT) {
					char *keyname;
					keyname = g_strdup_printf("form:%s:%s", form->auth_id, data->opt->name);
					g_hash_table_insert (ui_data->success_secrets,
							     keyname, g_strdup (data->entry_text));
				}

				if (data->opt->type == OC_FORM_OPT_PASSWORD) {
					/* store the password in the secret store */
					//int result;
					struct keyring_password *kp = g_new(struct keyring_password, 1);
					kp->description = g_strdup_printf(_("OpenConnect: %s: %s:%s"), ui_data->vpn_name, form->auth_id, data->opt->name);
					kp->password = g_strdup(data->entry_text);
					kp->vpn_uuid = g_strdup(ui_data->vpn_uuid);
					kp->auth_id = g_strdup(form->auth_id);
					kp->label = g_strdup(data->opt->name);

					g_hash_table_insert (ui_data->success_passwords,
							g_strdup(kp->description), kp);
				}
			}
			g_slice_free (ui_fragment_data, data);
		}
	}

	ui_data->form_grabbed = 0;
	g_mutex_unlock(&ui_data->form_mutex);

	if (response == AUTH_DIALOG_RESPONSE_LOGIN) {
		if (ui_data->newgroup)
			return OC_FORM_RESULT_NEWGROUP;
		else
			return OC_FORM_RESULT_OK;
	} else
		return OC_FORM_RESULT_CANCELLED;

}

static char* get_title(const char *vpn_name)
{
	if (vpn_name)
		return g_strdup_printf(_("Connect to VPN '%s'"), vpn_name);
	else
		return g_strdup(_("Connect to VPN"));
}

typedef struct cert_data {
	auth_ui_data *ui_data;
	char *cert_details;
	const char *reason;
} cert_data;

#if !OPENCONNECT_CHECK_VER(1,5)
static char *openconnect_get_cert_details(struct openconnect_info *vpninfo,
					  OPENCONNECT_X509 *cert)
{
        BIO *bp = BIO_new(BIO_s_mem());
        BUF_MEM *certinfo;
        char zero = 0;
        char *ret;

        X509_print_ex(bp, cert, 0, 0);
        BIO_write(bp, &zero, 1);
        BIO_get_mem_ptr(bp, &certinfo);

        ret = strdup(certinfo->data);
        BIO_free(bp);

        return ret;
}
#endif

static gboolean user_validate_cert(cert_data *data)
{
	auth_ui_data *ui_data = _ui_data; /* FIXME global */
	char *title;
	GtkWidget *dlg, *text, *scroll;
	GtkTextBuffer *buffer;
	int result;

	title = get_title(data->ui_data->vpn_name);
	dlg = gtk_message_dialog_new(NULL, 0, GTK_MESSAGE_QUESTION,
				     GTK_BUTTONS_OK_CANCEL,
	                             _("Certificate from VPN server \"%s\" failed verification.\n"
			             "Reason: %s\nDo you want to accept it?"),
			             openconnect_get_hostname(data->ui_data->vpninfo),
			             data->reason);
	gtk_window_set_skip_taskbar_hint(GTK_WINDOW(dlg), FALSE);
	gtk_window_set_skip_pager_hint(GTK_WINDOW(dlg), FALSE);
	gtk_window_set_title(GTK_WINDOW(dlg), title);
	gtk_window_set_default_size(GTK_WINDOW(dlg), 550, 600);
	gtk_window_set_resizable(GTK_WINDOW(dlg), TRUE);
	gtk_dialog_set_default_response(GTK_DIALOG(dlg), GTK_RESPONSE_CANCEL);

	g_free(title);

	scroll = gtk_scrolled_window_new(NULL, NULL);
	gtk_box_pack_start(GTK_BOX (gtk_dialog_get_content_area(GTK_DIALOG (dlg))), scroll, TRUE, TRUE, 0);
	gtk_widget_show(scroll);

	text = gtk_text_view_new();
	buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(text));
	gtk_text_buffer_set_text(buffer, data->cert_details, -1);
	gtk_text_view_set_editable(GTK_TEXT_VIEW(text), 0);
	gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW(text), FALSE);
	gtk_container_add(GTK_CONTAINER(scroll), text);
	gtk_widget_show(text);

	result = gtk_dialog_run(GTK_DIALOG(dlg));

	gtk_widget_destroy(dlg);

	g_mutex_lock (&ui_data->form_mutex);
	if (result == GTK_RESPONSE_OK)
		data->ui_data->cert_response = CERT_ACCEPTED;
	else
		data->ui_data->cert_response = CERT_DENIED;
	g_cond_signal (&ui_data->cert_response_changed);
	g_mutex_unlock (&ui_data->form_mutex);

	return FALSE;
}

/* runs in worker thread */
static int validate_peer_cert(void *cbdata,
#if !OPENCONNECT_CHECK_VER(5,0)
			      OPENCONNECT_X509 *peer_cert,
#endif
			      const char *reason)
{
	auth_ui_data *ui_data = cbdata;
	int ret = 0;
	cert_data *data;
	char *certkey;
	char *accepted_hash = NULL;
#if OPENCONNECT_CHECK_VER(5,0)
	const char *fingerprint = openconnect_get_peer_cert_hash(ui_data->vpninfo);
#else
	char fingerprint[41];

	ret = openconnect_get_cert_sha1(ui_data->vpninfo, peer_cert, fingerprint);
	if (ret)
		return ret;

#define openconnect_check_peer_cert_hash(v, h) strcmp(h, fingerprint)
#define openconnect_get_peer_cert_details(v) openconnect_get_cert_details(v, peer_cert);
#endif

	certkey = g_strdup_printf ("certificate:%s:%d",
				   openconnect_get_hostname(ui_data->vpninfo),
				   openconnect_get_port(ui_data->vpninfo));

	accepted_hash = g_hash_table_lookup (ui_data->secrets, certkey);
	if (accepted_hash && !openconnect_check_peer_cert_hash(ui_data->vpninfo, accepted_hash))
		goto accepted;

	data = g_slice_new(cert_data);
	data->ui_data = ui_data; /* FIXME uses global */
	data->cert_details = openconnect_get_peer_cert_details(ui_data->vpninfo);
	data->reason = reason;

	g_mutex_lock(&ui_data->form_mutex);

	ui_data->cert_response = CERT_USER_NOT_READY;
	g_idle_add((GSourceFunc)user_validate_cert, data);

	/* wait for user to accept or cancel */
	while (ui_data->cert_response == CERT_USER_NOT_READY)
		g_cond_wait(&ui_data->cert_response_changed, &ui_data->form_mutex);

	openconnect_free_cert_info(data->ui_data->vpninfo, data->cert_details);
	g_slice_free(cert_data, data);

	if (ui_data->cert_response == CERT_ACCEPTED)
		ret = 0;
	else
		ret = -EINVAL;

	g_mutex_unlock (&ui_data->form_mutex);

 accepted:
	if (!ret) {
		g_hash_table_insert (ui_data->secrets, certkey,
				     g_strdup(fingerprint));
		certkey = NULL;
	}

	g_free (certkey);
	return ret;
}

static gboolean get_autoconnect(GHashTable *secrets)
{
	char *autoconnect = g_hash_table_lookup (secrets, "autoconnect");

	if (autoconnect && !strcmp(autoconnect, "yes"))
		return TRUE;

	return FALSE;
}

static gboolean get_save_passwords(GHashTable *secrets)
{
	char *save = g_hash_table_lookup (secrets, "save_passwords");

	if (save && !strcmp(save, "yes"))
		return TRUE;

	return FALSE;
}

static int parse_xmlconfig(gchar *xmlconfig)
{
	xmlDocPtr xml_doc;
	xmlNode *xml_node, *xml_node2;
	struct vpnhost *newhost, **list_end;

	list_end = &vpnhosts->next;
	/* gateway may be there already */
	while (*list_end) {
		list_end = &(*list_end)->next;
	}

	xml_doc = xmlReadMemory(xmlconfig, strlen(xmlconfig), "noname.xml", NULL, 0);

	xml_node = xmlDocGetRootElement(xml_doc);
	for (xml_node = xml_node->children; xml_node; xml_node = xml_node->next) {
                if (xml_node->type == XML_ELEMENT_NODE &&
                    !strcmp((char *)xml_node->name, "ServerList")) {

                        for (xml_node = xml_node->children; xml_node;
                             xml_node = xml_node->next) {

                                if (xml_node->type == XML_ELEMENT_NODE &&
                                    !strcmp((char *)xml_node->name, "HostEntry")) {
                                        int match = 0;

					newhost = malloc(sizeof(*newhost));
					if (!newhost)
						return -ENOMEM;

					memset(newhost, 0, sizeof(*newhost));
                                        for (xml_node2 = xml_node->children;
                                             match >= 0 && xml_node2; xml_node2 = xml_node2->next) {

                                                if (xml_node2->type != XML_ELEMENT_NODE)
                                                        continue;

                                                if (!strcmp((char *)xml_node2->name, "HostName")) {
                                                        char *content = (char *)xmlNodeGetContent(xml_node2);
							newhost->hostname = content;
						} else if (!strcmp((char *)xml_node2->name, "HostAddress")) {
                                                        char *content = (char *)xmlNodeGetContent(xml_node2);
							newhost->hostaddress = content;
						} else if (!strcmp((char *)xml_node2->name, "UserGroup")) {
                                                        char *content = (char *)xmlNodeGetContent(xml_node2);
							newhost->usergroup = content;
						}
					}
					if (newhost->hostname && newhost->hostaddress) {
						*list_end = newhost;
						list_end = &newhost->next;

						if (!strcasecmp(newhost->hostaddress, vpnhosts->hostaddress) &&
						    !strcasecmp(newhost->usergroup ?: "", vpnhosts->usergroup ?: "")) {
							/* Remove originally configured host if it's in the list */
							struct vpnhost *tmp = vpnhosts->next;
							free(vpnhosts);
							vpnhosts = tmp;
						}

                                        } else
						free(newhost);
                                }
                        }
			break;
                }
        }
        xmlFreeDoc(xml_doc);
	return 0;
}

static int get_config (GHashTable *options, GHashTable *secrets,
		       struct openconnect_info *vpninfo)
{
	char *proxy;
	char *xmlconfig;
	char *hostname;
	char *group;
	char *csd;
	char *sslkey, *cert;
	char *csd_wrapper;
	char *pem_passphrase_fsid;
	char *cafile;
	char *token_mode;
	char *token_secret;

	hostname = g_hash_table_lookup (options, NM_OPENCONNECT_KEY_GATEWAY);
	if (!hostname) {
		fprintf(stderr, "No gateway configured\n");
		return -EINVAL;
	}

	/* add gateway to host list */
	vpnhosts = malloc(sizeof(*vpnhosts));
	if (!vpnhosts)
		return -ENOMEM;
	vpnhosts->hostname = g_strdup(hostname);
	group = strchr(vpnhosts->hostname, '/');
	if (group) {
		*(group++) = 0;
		vpnhosts->usergroup = g_strdup(group);
	} else
		vpnhosts->usergroup = NULL;
	vpnhosts->hostaddress = g_strdup (hostname);
	vpnhosts->next = NULL;

	lasthost = g_hash_table_lookup (secrets, "lasthost");

	xmlconfig = g_hash_table_lookup (secrets, "xmlconfig");
	if (xmlconfig) {
		GChecksum *sha1;
		gchar *config_str;
		gsize config_len;
		const char *sha1_text;

		config_str = (gchar *)g_base64_decode (xmlconfig, &config_len);

		sha1 = g_checksum_new (G_CHECKSUM_SHA1);
		g_checksum_update (sha1, (gpointer) config_str, config_len);
		sha1_text = g_checksum_get_string(sha1);

		openconnect_set_xmlsha1 (vpninfo, (char *)sha1_text, strlen(sha1_text) + 1);
		g_checksum_free(sha1);
		
		parse_xmlconfig (config_str);
	}

	cafile = g_hash_table_lookup (options, NM_OPENCONNECT_KEY_CACERT);
	if (cafile)
		openconnect_set_cafile(vpninfo, OC3DUP (cafile));

	csd = g_hash_table_lookup (options, NM_OPENCONNECT_KEY_CSD_ENABLE);
	if (csd && !strcmp(csd, "yes")) {
		/* We're not running as root; we can't setuid(). */
		csd_wrapper = g_hash_table_lookup (options,
						   NM_OPENCONNECT_KEY_CSD_WRAPPER);
		if (csd_wrapper && !csd_wrapper[0])
			csd_wrapper = NULL;

		openconnect_setup_csd(vpninfo, getuid(), 1, OC3DUP (csd_wrapper));
	}

	proxy = g_hash_table_lookup (options, NM_OPENCONNECT_KEY_PROXY);
	if (proxy && proxy[0] && openconnect_set_http_proxy(vpninfo, OC3DUP (proxy)))
		return -EINVAL;

	cert = g_hash_table_lookup (options, NM_OPENCONNECT_KEY_USERCERT);
	sslkey = g_hash_table_lookup (options, NM_OPENCONNECT_KEY_PRIVKEY);
	openconnect_set_client_cert (vpninfo, OC3DUP (cert), OC3DUP (sslkey));

	pem_passphrase_fsid = g_hash_table_lookup (options,
						   NM_OPENCONNECT_KEY_PEM_PASSPHRASE_FSID);
	if (pem_passphrase_fsid && cert && !strcmp(pem_passphrase_fsid, "yes"))
		openconnect_passphrase_from_fsid(vpninfo);

	token_mode = g_hash_table_lookup (options, NM_OPENCONNECT_KEY_TOKEN_MODE);
	token_secret = g_hash_table_lookup (secrets, NM_OPENCONNECT_KEY_TOKEN_SECRET);
	if (!token_secret || !token_secret[0])
		token_secret = g_hash_table_lookup (options, NM_OPENCONNECT_KEY_TOKEN_SECRET);
	if (token_mode) {
		int ret = 0;

		if (!strcmp(token_mode, "manual") && token_secret)
			ret = __openconnect_set_token_mode(vpninfo, OC_TOKEN_MODE_STOKEN, token_secret);
		else if (!strcmp(token_mode, "stokenrc"))
			ret = __openconnect_set_token_mode(vpninfo, OC_TOKEN_MODE_STOKEN, NULL);
		else if (!strcmp(token_mode, "totp") && token_secret)
			ret = __openconnect_set_token_mode(vpninfo, OC_TOKEN_MODE_TOTP, token_secret);
#if OPENCONNECT_CHECK_VER(3,4)
		else if (!strcmp(token_mode, "hotp") && token_secret)
			ret = __openconnect_set_token_mode(vpninfo, OC_TOKEN_MODE_HOTP, token_secret);
#endif

		if (ret)
			fprintf(stderr, "Failed to initialize software token: %d\n", ret);
	}

	return 0;
}

static void populate_vpnhost_combo(auth_ui_data *ui_data)
{
	struct vpnhost *host;
	int i = 0;
	GtkComboBoxText *combo = GTK_COMBO_BOX_TEXT (ui_data->combo);

	for (host = vpnhosts; host; host = host->next) {
		gtk_combo_box_text_append_text(combo, host->hostname);

		if (i == 0 ||
		    (lasthost && !strcmp(host->hostname, lasthost)))
			gtk_combo_box_set_active(GTK_COMBO_BOX (combo), i);
		i++;

	}
}

#if OPENCONNECT_CHECK_VER(3,4)
static int update_token(void *cbdata, const char *tok)
{
	auth_ui_data *ui_data = cbdata;
	g_hash_table_insert (ui_data->secrets, g_strdup (NM_OPENCONNECT_KEY_TOKEN_SECRET),
			     g_strdup(tok));

	return 0;
}
#endif

static int write_new_config(void *cbdata, write_config_const char *buf, int buflen)
{
	auth_ui_data *ui_data = cbdata;
	g_hash_table_insert (ui_data->secrets, g_strdup ("xmlconfig"),
			     g_base64_encode ((guchar *)buf, buflen));

	return 0;
}

static void autocon_toggled(GtkWidget *widget)
{
	auth_ui_data *ui_data = _ui_data; /* FIXME global */
	gchar *enabled;

	if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON(widget)))
		enabled = g_strdup ("yes");
	else
		enabled = g_strdup ("no");

	g_hash_table_insert (ui_data->secrets, g_strdup ("autoconnect"), enabled);
}

static void savepass_toggled(GtkWidget *widget)
{
	auth_ui_data *ui_data = _ui_data; /* FIXME global */
	gchar *enabled;

	if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON(widget)))
		enabled = g_strdup ("yes");
	else {
		enabled = g_strdup ("no");
		secret_password_clear (&openconnect_secret_schema, NULL, NULL, NULL,
		                       "vpn_uuid", ui_data->vpn_uuid,
		                       NULL);
	}
	g_hash_table_insert (ui_data->secrets, g_strdup ("save_passwords"), enabled);
}

static void scroll_log(GtkTextBuffer *log, GtkTextView *view)
{
	GtkTextMark *mark;

	g_return_if_fail(GTK_IS_TEXT_VIEW(view));

	mark = gtk_text_buffer_get_insert(log);
	gtk_text_view_scroll_to_mark(view, mark, 0.0, FALSE, 0.0, 0.0);
}

/* NOTE: write_progress_real() will free the given string */
static gboolean write_progress_real(char *message)
{
	auth_ui_data *ui_data = _ui_data; /* FIXME global */
	GtkTextIter iter;

	g_return_val_if_fail(message, FALSE);

	gtk_text_buffer_get_end_iter(ui_data->log, &iter);
	gtk_text_buffer_insert(ui_data->log, &iter, message, -1);

	g_free(message);

	return FALSE;
}

/* NOTE: write_progress_real() will free the given string */
static gboolean write_notice_real(char *message)
{
	auth_ui_data *ui_data = _ui_data; /* FIXME global */

	g_return_val_if_fail(message, FALSE);

	ssl_box_add_notice(ui_data, message);
	g_free(message);

	return FALSE;
}

/* runs in worker thread */
static void write_progress(void *cbdata, int level, const char *fmt, ...)
{
	va_list args;
	char *msg;

	va_start(args, fmt);
	msg = g_strdup_vprintf(fmt, args);
	va_end(args);

	if (level <= PRG_ERR) {
		g_idle_add((GSourceFunc)write_notice_real, g_strdup(msg));
	}

	if (level <= PRG_DEBUG)
		g_idle_add((GSourceFunc)write_progress_real, msg);
	else
		g_free(msg);
}

static gboolean hash_merge_one (gpointer key, gpointer value, gpointer new_hash)
{
	g_hash_table_insert (new_hash, key, value);
	return TRUE;
}

static void hash_table_merge (GHashTable *old_hash, GHashTable *new_hash)
{
	g_hash_table_foreach_steal (old_hash, &hash_merge_one, new_hash);
}

static gboolean cookie_obtained(auth_ui_data *ui_data)
{
	ui_data->getting_cookie = FALSE;
	gtk_widget_hide (ui_data->getting_form_label);

	if (ui_data->cancelled) {
		/* user has chosen a new host, start from beginning */
		g_hash_table_remove_all (ui_data->success_secrets);
		g_hash_table_remove_all (ui_data->success_passwords);
		connect_host(ui_data);
		return FALSE;
	}

	if (ui_data->cookie_retval < 0) {
		/* error while getting cookie */
		if (ui_data->last_notice_icon) {
			gtk_image_set_from_icon_name(GTK_IMAGE (ui_data->last_notice_icon),
						     "dialog-error",
						     GTK_ICON_SIZE_DIALOG);
			gtk_widget_show_all(ui_data->ssl_box);
			gtk_widget_set_sensitive(ui_data->cancel_button, FALSE);
		}
	} else if (!ui_data->cookie_retval) {
		const void *cert;
		gchar *key, *value;

		/* got cookie */

		/* Merge in the secrets which we only wanted to remember if
		   the connection was successful (lasthost, form entries) */
		hash_table_merge (ui_data->success_secrets, ui_data->secrets);

		/* Merge in the three *real* secrets that are actually used
		   by nm-openconnect-service to make the connection */
		key = g_strdup (NM_OPENCONNECT_KEY_GATEWAY);
		value = g_strdup_printf ("%s:%d",
					 openconnect_get_hostname(ui_data->vpninfo),
					 openconnect_get_port(ui_data->vpninfo));
		g_hash_table_insert (ui_data->secrets, key, value);

		key = g_strdup (NM_OPENCONNECT_KEY_COOKIE);
		value = g_strdup (openconnect_get_cookie (ui_data->vpninfo));
		g_hash_table_insert (ui_data->secrets, key, value);
		openconnect_clear_cookie(ui_data->vpninfo);

#if OPENCONNECT_CHECK_VER(5,0)
		cert = openconnect_get_peer_cert_hash (ui_data->vpninfo);
		if (cert) {
			key = g_strdup (NM_OPENCONNECT_KEY_GWCERT);
			value = g_strdup (cert);
			g_hash_table_insert (ui_data->secrets, key, value);
		}
#else
		cert = openconnect_get_peer_cert (ui_data->vpninfo);
		if (cert) {
			key = g_strdup (NM_OPENCONNECT_KEY_GWCERT);
			value = g_malloc0 (41);
			openconnect_get_cert_sha1(ui_data->vpninfo, (void *)cert, value);
			g_hash_table_insert (ui_data->secrets, key, value);
		}
#endif
		if (get_save_passwords(ui_data->secrets)) {
			g_hash_table_foreach(ui_data->success_passwords,
					     keyring_store_passwords,
					     NULL);
		}

		gtk_main_quit();
	} else {
		/* no cookie; user cancellation */
		gtk_widget_show (ui_data->no_form_label);
	}

	g_hash_table_remove_all (ui_data->success_secrets);
	g_hash_table_remove_all (ui_data->success_passwords);

	return FALSE;
}

static gpointer obtain_cookie (auth_ui_data *ui_data)
{
	int ret;
	char cancelbuf;

	ret = openconnect_obtain_cookie(ui_data->vpninfo);

	/* Suck out the poison */
	while (read(ui_data->cancel_pipes[0], &cancelbuf, 1) == 1)
		;
	ui_data->cookie_retval = ret;
	g_idle_add ((GSourceFunc)cookie_obtained, ui_data);

	return NULL;
}

static void connect_host(auth_ui_data *ui_data)
{
	GThread *thread;
	vpnhost *host;
	int i;
	int host_nr;
	char cancelbuf;

	ui_data->cancelled = FALSE;
	ui_data->getting_cookie = TRUE;

	g_mutex_lock (&ui_data->form_mutex);
	ui_data->form_retval = NULL;
	g_mutex_unlock (&ui_data->form_mutex);

	ssl_box_clear(ui_data);
	gtk_widget_show(ui_data->getting_form_label);
	gtk_widget_set_sensitive (ui_data->cancel_button, TRUE);
	while (read(ui_data->cancel_pipes[0], &cancelbuf, 1) == 1)
		;
	/* reset ssl context.
	 * TODO: this is probably not the way to go... */
	openconnect_reset_ssl(ui_data->vpninfo);

	host_nr = gtk_combo_box_get_active(GTK_COMBO_BOX(ui_data->combo));
	host = vpnhosts;
	for (i = 0; i < host_nr; i++)
		host = host->next;

	if (openconnect_parse_url(ui_data->vpninfo, host->hostaddress)) {
		fprintf(stderr, "Failed to parse server URL '%s'\n",
			host->hostaddress);
		openconnect_set_hostname (ui_data->vpninfo, OC3DUP (host->hostaddress));
	}

	if (!openconnect_get_urlpath(ui_data->vpninfo) && host->usergroup)
		openconnect_set_urlpath(ui_data->vpninfo, OC3DUP (host->usergroup));


	g_hash_table_insert (ui_data->success_secrets, g_strdup("lasthost"),
			     g_strdup(host->hostname));

	thread = g_thread_new("obtain_cookie", (GThreadFunc)obtain_cookie, ui_data);
	g_thread_unref(thread);
}


static void queue_connect_host(auth_ui_data *ui_data)
{
	ssl_box_clear(ui_data);
	gtk_widget_show(ui_data->getting_form_label);
	gtk_widget_hide(ui_data->no_form_label);

	if (!ui_data->getting_cookie) {
		connect_host(ui_data);
	} else if (!ui_data->cancelled) {
		/* set state to cancelled. Current challenge-response-
		 * conversation will not be shown to user, and cookie_obtained()
		 * will start a new one conversation */
		ui_data->cancelled = TRUE;
		gtk_dialog_response(GTK_DIALOG(ui_data->dialog), AUTH_DIALOG_RESPONSE_CANCEL);
	}
}

static void dialog_response (GtkDialog *dialog, int response, auth_ui_data *ui_data)
{
	switch (response) {
	case AUTH_DIALOG_RESPONSE_CANCEL:
		if (write(ui_data->cancel_pipes[1], "x", 1) < 0) {
			/* Pfft. Not a lot we can do about it */
		}
		/* Fall through... */
	case AUTH_DIALOG_RESPONSE_LOGIN:
		ssl_box_clear(ui_data);
		if (ui_data->getting_cookie)
			gtk_widget_show (ui_data->getting_form_label);
		g_mutex_lock (&ui_data->form_mutex);
		ui_data->form_retval = GINT_TO_POINTER(response);
		g_cond_signal (&ui_data->form_retval_changed);
		g_mutex_unlock (&ui_data->form_mutex);
		break;
	case GTK_RESPONSE_CLOSE:
		gtk_main_quit();
		break;
	default:
		;
	}
}

static void cancel_clicked (GtkButton *btn, auth_ui_data *ui_data)
{
	gtk_dialog_response (GTK_DIALOG(ui_data->dialog), AUTH_DIALOG_RESPONSE_CANCEL);
}

static void login_clicked (GtkButton *btn, auth_ui_data *ui_data)
{
	gtk_dialog_response (GTK_DIALOG(ui_data->dialog), AUTH_DIALOG_RESPONSE_LOGIN);
}

static void build_main_dialog(auth_ui_data *ui_data)
{
	char *title;
	GtkWidget *vbox, *hbox, *label, *frame, *frame_box;
	GtkWidget *exp, *scrolled, *view, *autocon, *save_pass;

	gtk_window_set_default_icon_name("dialog-password");

	title = get_title(ui_data->vpn_name);
	ui_data->dialog = gtk_dialog_new_with_buttons(title, NULL, GTK_DIALOG_MODAL,
						      _("_Close"), GTK_RESPONSE_CLOSE,
						      NULL);
	g_signal_connect (ui_data->dialog, "response", G_CALLBACK(dialog_response), ui_data);
	gtk_window_set_default_size(GTK_WINDOW(ui_data->dialog), 350, 300);
	g_signal_connect_swapped(ui_data->dialog, "destroy",
				 G_CALLBACK(gtk_main_quit), NULL);
	g_free(title);

	vbox = gtk_box_new (GTK_ORIENTATION_VERTICAL, 8);
	gtk_box_pack_start(GTK_BOX (gtk_dialog_get_content_area(GTK_DIALOG (ui_data->dialog))), vbox, TRUE, TRUE, 0);
	gtk_container_set_border_width(GTK_CONTAINER(vbox), 8);
	gtk_widget_show(vbox);

	hbox = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 4);
	gtk_box_pack_start(GTK_BOX(vbox), hbox, FALSE, FALSE, 0);
	gtk_widget_show(hbox);

	label = gtk_label_new(_("VPN host"));
	gtk_box_pack_start(GTK_BOX(hbox), label, FALSE, FALSE, 0);
	gtk_widget_show(label);

	ui_data->combo = gtk_combo_box_text_new();
	populate_vpnhost_combo(ui_data);
	gtk_box_pack_start(GTK_BOX(hbox), ui_data->combo, TRUE, TRUE, 0);
	g_signal_connect_swapped(ui_data->combo, "changed",
	                         G_CALLBACK(queue_connect_host), ui_data);
	gtk_widget_show(ui_data->combo);

	ui_data->connect_button = gtk_button_new_with_mnemonic(_("C_onnect"));
	gtk_box_pack_end(GTK_BOX(hbox), ui_data->connect_button, FALSE, FALSE, 0);
	gtk_widget_grab_focus(ui_data->connect_button);
	g_signal_connect_swapped(ui_data->connect_button, "clicked",
				 G_CALLBACK(queue_connect_host), ui_data);
	gtk_widget_show(ui_data->connect_button);
	if (vpnhosts->next) {
		autocon = gtk_check_button_new_with_label(_("Automatically start connecting next time"));
		gtk_box_pack_start(GTK_BOX(vbox), autocon, FALSE, FALSE, 0);
		if (get_autoconnect (ui_data->secrets))
			gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(autocon), 1);
		g_signal_connect(autocon, "toggled", G_CALLBACK(autocon_toggled), NULL);
		gtk_widget_show(autocon);
	}
	frame = gtk_frame_new(NULL);
	gtk_box_pack_start(GTK_BOX(vbox), frame, TRUE, TRUE, 0);
	gtk_widget_set_size_request(frame, -1, -1);
	gtk_widget_show(frame);

	frame_box = gtk_box_new (GTK_ORIENTATION_VERTICAL, 4);
	gtk_container_set_border_width(GTK_CONTAINER(frame_box), 8);
	gtk_container_add(GTK_CONTAINER(frame), frame_box);
	gtk_widget_show(frame_box);

	ui_data->no_form_label = gtk_label_new(_("Select a host to fetch the login form"));
	gtk_widget_set_sensitive(ui_data->no_form_label, FALSE);
	gtk_box_pack_start(GTK_BOX(frame_box), ui_data->no_form_label, FALSE, FALSE, 0);
	gtk_widget_show(ui_data->no_form_label);

	ui_data->getting_form_label = gtk_label_new(_("Contacting host, please wait..."));
	gtk_widget_set_sensitive(ui_data->getting_form_label, FALSE);
	gtk_box_pack_start(GTK_BOX(frame_box), ui_data->getting_form_label, FALSE, FALSE, 0);

	ui_data->ssl_box = gtk_box_new (GTK_ORIENTATION_VERTICAL, 4);
	gtk_box_pack_start(GTK_BOX(frame_box), ui_data->ssl_box, FALSE, FALSE, 0);
	gtk_widget_show(ui_data->ssl_box);

	hbox = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 6);
	gtk_box_pack_end(GTK_BOX(frame_box), hbox, FALSE, FALSE, 0);
	gtk_widget_show(hbox);

	ui_data->login_button = gtk_button_new_with_mnemonic(_("_Login"));
	gtk_box_pack_end(GTK_BOX(hbox), ui_data->login_button, FALSE, FALSE, 0);
	g_signal_connect (ui_data->login_button, "clicked", G_CALLBACK(login_clicked), ui_data);
	gtk_widget_set_sensitive (ui_data->login_button, FALSE);
	gtk_widget_show(ui_data->login_button);

	ui_data->cancel_button = gtk_button_new_with_mnemonic(_("_Cancel"));
	gtk_box_pack_end(GTK_BOX(hbox), ui_data->cancel_button, FALSE, FALSE, 0);
	g_signal_connect (ui_data->cancel_button, "clicked", G_CALLBACK(cancel_clicked), ui_data);
	gtk_widget_set_sensitive (ui_data->cancel_button, FALSE);
	gtk_widget_show(ui_data->cancel_button);

	save_pass = gtk_check_button_new_with_label(_("Save passwords"));
	gtk_box_pack_start(GTK_BOX(hbox), save_pass, FALSE, FALSE, 0);
	if (get_save_passwords (ui_data->secrets))
		gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(save_pass), 1);
	g_signal_connect(save_pass, "toggled", G_CALLBACK(savepass_toggled), NULL);
	gtk_widget_show(save_pass);


	exp = gtk_expander_new(_("Log"));
	gtk_box_pack_end(GTK_BOX(vbox), exp, FALSE, FALSE, 0);
	gtk_widget_show(exp);

	scrolled = gtk_scrolled_window_new(NULL, NULL);
	gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolled),
				       GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
	gtk_widget_set_size_request(scrolled, -1, 75);
	gtk_container_add(GTK_CONTAINER(exp), scrolled);
	gtk_widget_show(scrolled);

	view = gtk_text_view_new();
	gtk_text_view_set_editable(GTK_TEXT_VIEW(view), FALSE);
	gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW(view), FALSE);
	gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(view), GTK_WRAP_WORD_CHAR);
	gtk_text_view_set_left_margin(GTK_TEXT_VIEW(view), 5);
	gtk_text_view_set_right_margin(GTK_TEXT_VIEW(view), 5);
	gtk_text_view_set_indent(GTK_TEXT_VIEW(view), -10);
	gtk_container_add(GTK_CONTAINER(scrolled), view);
	gtk_widget_show(view);

	ui_data->log = gtk_text_view_get_buffer(GTK_TEXT_VIEW(view));
	g_signal_connect(ui_data->log, "changed", G_CALLBACK(scroll_log), view);
}

static auth_ui_data *init_ui_data (char *vpn_name, GHashTable *options, GHashTable *secrets, char *vpn_uuid)
{
	auth_ui_data *ui_data;

	ui_data = g_slice_new0(auth_ui_data);

	ui_data->form_entries = g_queue_new();
	g_mutex_init(&ui_data->form_mutex);
	g_cond_init(&ui_data->form_retval_changed);
	g_cond_init(&ui_data->form_shown_changed);
	g_cond_init(&ui_data->cert_response_changed);
	ui_data->vpn_name = vpn_name;
	ui_data->vpn_uuid = vpn_uuid;
	ui_data->options = options;
	ui_data->secrets = secrets;
	ui_data->success_secrets = g_hash_table_new_full (g_str_hash, g_str_equal,
							  g_free, g_free);
	ui_data->success_passwords = g_hash_table_new_full (g_str_hash, g_str_equal,
							  g_free, keyring_password_free);
	if (pipe(ui_data->cancel_pipes)) {
		/* This should never happen, and the world is probably about
		   to come crashing down around our ears. But attempt to cope
		   by just disabling the cancellation support... */
		ui_data->cancel_pipes[0] = -1;
		ui_data->cancel_pipes[1] = -1;
	}
	g_unix_set_fd_nonblocking(ui_data->cancel_pipes[0], TRUE, NULL);
	g_unix_set_fd_nonblocking(ui_data->cancel_pipes[1], TRUE, NULL);

	ui_data->vpninfo = (void *)openconnect_vpninfo_new("OpenConnect VPN Agent (NetworkManager)",
							   validate_peer_cert, write_new_config,
							   nm_process_auth_form, write_progress,
							   ui_data);

#if OPENCONNECT_CHECK_VER(1,4)
	openconnect_set_cancel_fd (ui_data->vpninfo, ui_data->cancel_pipes[0]);
#endif  

#if 0
	ui_data->vpninfo->proxy_factory = px_proxy_factory_new();
#endif

	return ui_data;
}

static void wait_for_quit (void)
{
	GString *str;
	char c;
	ssize_t n;
	time_t start;

	str = g_string_sized_new (10);
	start = time (NULL);
	do {
		errno = 0;
		n = read (0, &c, 1);
		if (n == 0 || (n < 0 && errno == EAGAIN))
			g_usleep (G_USEC_PER_SEC / 10);
		else if (n == 1) {
			g_string_append_c (str, c);
			if (strstr (str->str, "QUIT") || (str->len > 10))
				break;
		} else
			break;
	} while (time (NULL) < start + 20);
	g_string_free (str, TRUE);
}

static struct option long_options[] = {
	{"reprompt", 0, 0, 'r'},
	{"uuid", 1, 0, 'u'},
	{"name", 1, 0, 'n'},
	{"service", 1, 0, 's'},
	{"allow-interaction", 0, 0, 'i'},
	{NULL, 0, 0, 0},
};

int main (int argc, char **argv)
{
	char *vpn_name = NULL, *vpn_uuid = NULL, *vpn_service = NULL;
	GHashTable *options = NULL, *secrets = NULL;
	gboolean allow_interaction = FALSE;
	GHashTableIter iter;
	gchar *key, *value;
	int opt;

	while ((opt = getopt_long(argc, argv, "ru:n:s:i", long_options, NULL))) {
		if (opt < 0)
			break;

		switch(opt) {
		case 'r':
			/* Reprompt does nothing */
			break;

		case 'i':
			allow_interaction = TRUE;
			break;

		case 'u':
			vpn_uuid = optarg;
			break;

		case 'n':
			vpn_name = optarg;
			break;

		case 's':
			vpn_service = optarg;
			break;

		default:
			fprintf(stderr, "Unknown option\n");
			return 1;
		}
	}

	if (!allow_interaction)
		return 0;

	if (optind != argc) {
		fprintf(stderr, "Superfluous command line options\n");
		return 1;
	}

	if (!vpn_uuid || !vpn_name || !vpn_service) {
		fprintf (stderr, "Have to supply UUID, name, and service\n");
		return 1;
	}

	if (strcmp(vpn_service, NM_DBUS_SERVICE_OPENCONNECT) != 0) {
		fprintf (stderr, "This dialog only works with the '%s' service\n",
			 NM_DBUS_SERVICE_OPENCONNECT);
		return 1;
	}

	if (!nm_vpn_plugin_utils_read_vpn_details (0, &options, &secrets)) {
		fprintf (stderr, "Failed to read '%s' (%s) data and secrets from stdin.\n",
		         vpn_name, vpn_uuid);
		return 1;
	}

	gtk_init(0, NULL);

	_ui_data = init_ui_data(vpn_name, options, secrets, vpn_uuid);
	if (get_config(options, secrets, _ui_data->vpninfo)) {
		fprintf(stderr, "Failed to find VPN UUID %s\n", vpn_uuid);
		return 1;
	}

#if OPENCONNECT_CHECK_VER(3,4)
	openconnect_set_token_callbacks (_ui_data->vpninfo, _ui_data, NULL, update_token);
#endif

	build_main_dialog(_ui_data);

	openconnect_init_ssl();

	/* Start connecting now if there's only one host. Or if configured to */
	if (!vpnhosts->next || get_autoconnect (secrets))
		queue_connect_host(_ui_data);

	gtk_window_present(GTK_WINDOW(_ui_data->dialog));
	gtk_main();

	/* Dump all secrets to stdout */
	g_hash_table_iter_init (&iter, _ui_data->secrets);
	while (g_hash_table_iter_next (&iter, (gpointer *)&key,
				       (gpointer *)&value))
		printf("%s\n%s\n", key, value);

	printf("\n\n");
	fflush(stdout);

	wait_for_quit ();

	return 0;
}
