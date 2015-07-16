/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/***************************************************************************
 * nm-openconnect.h : GNOME UI dialogs for configuring openconnect VPN connections
 *
 * Copyright (C) 2008 Dan Williams, <dcbw@redhat.com>
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

#ifndef _NM_OPENCONNECT_H_
#define _NM_OPENCONNECT_H_

#include <glib-object.h>

#define OPENCONNECT_TYPE_PLUGIN_UI            (openconnect_plugin_ui_get_type ())
#define OPENCONNECT_PLUGIN_UI(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), OPENCONNECT_TYPE_PLUGIN_UI, OpenconnectPluginUi))
#define OPENCONNECT_PLUGIN_UI_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), OPENCONNECT_TYPE_PLUGIN_UI, OpenconnectPluginUiClass))
#define OPENCONNECT_IS_PLUGIN_UI(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), OPENCONNECT_TYPE_PLUGIN_UI))
#define OPENCONNECT_IS_PLUGIN_UI_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), OPENCONNECT_TYPE_PLUGIN_UI))
#define OPENCONNECT_PLUGIN_UI_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), OPENCONNECT_TYPE_PLUGIN_UI, OpenconnectPluginUiClass))

typedef struct _OpenconnectPluginUi OpenconnectPluginUi;
typedef struct _OpenconnectPluginUiClass OpenconnectPluginUiClass;

struct _OpenconnectPluginUi {
	GObject parent;
};

struct _OpenconnectPluginUiClass {
	GObjectClass parent;
};

GType openconnect_plugin_ui_get_type (void);


#define OPENCONNECT_TYPE_PLUGIN_UI_WIDGET            (openconnect_plugin_ui_widget_get_type ())
#define OPENCONNECT_PLUGIN_UI_WIDGET(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), OPENCONNECT_TYPE_PLUGIN_UI_WIDGET, OpenconnectPluginUiWidget))
#define OPENCONNECT_PLUGIN_UI_WIDGET_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), OPENCONNECT_TYPE_PLUGIN_UI_WIDGET, OpenconnectPluginUiWidgetClass))
#define OPENCONNECT_IS_PLUGIN_UI_WIDGET(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), OPENCONNECT_TYPE_PLUGIN_UI_WIDGET))
#define OPENCONNECT_IS_PLUGIN_UI_WIDGET_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), OPENCONNECT_TYPE_PLUGIN_UI_WIDGET))
#define OPENCONNECT_PLUGIN_UI_WIDGET_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), OPENCONNECT_TYPE_PLUGIN_UI_WIDGET, OpenconnectPluginUiWidgetClass))

typedef struct _OpenconnectPluginUiWidget OpenconnectPluginUiWidget;
typedef struct _OpenconnectPluginUiWidgetClass OpenconnectPluginUiWidgetClass;

struct _OpenconnectPluginUiWidget {
	GObject parent;
};

struct _OpenconnectPluginUiWidgetClass {
	GObjectClass parent;
};

GType openconnect_plugin_ui_widget_get_type (void);

#endif	/* _NM_OPENCONNECT_H_ */

