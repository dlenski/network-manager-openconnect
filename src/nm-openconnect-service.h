/* -*- Mode: C; tab-width: 5; indent-tabs-mode: t; c-basic-offset: 5 -*- */

#ifndef NM_OPENCONNECT_PLUGIN_H
#define NM_OPENCONNECT_PLUGIN_H

#include <glib/gtypes.h>
#include <glib-object.h>
#include <nm-vpn-plugin.h>

#define NM_TYPE_OPENCONNECT_PLUGIN            (nm_openconnect_plugin_get_type ())
#define NM_OPENCONNECT_PLUGIN(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_OPENCONNECT_PLUGIN, NMOPENCONNECTPlugin))
#define NM_OPENCONNECT_PLUGIN_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_OPENCONNECT_PLUGIN, NMOPENCONNECTPluginClass))
#define NM_IS_OPENCONNECT_PLUGIN(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_OPENCONNECT_PLUGIN))
#define NM_IS_OPENCONNECT_PLUGIN_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), NM_TYPE_OPENCONNECT_PLUGIN))
#define NM_OPENCONNECT_PLUGIN_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_OPENCONNECT_PLUGIN, NMOPENCONNECTPluginClass))

#define NM_DBUS_SERVICE_OPENCONNECT    "org.freedesktop.NetworkManager.openconnect"
#define NM_DBUS_INTERFACE_OPENCONNECT  "org.freedesktop.NetworkManager.openconnect"
#define NM_DBUS_PATH_OPENCONNECT       "/org/freedesktop/NetworkManager/openconnect"

#define NM_OPENCONNECT_KEY_GATEWAY "gateway"
#define NM_OPENCONNECT_KEY_COOKIE "cookie"
#define NM_OPENCONNECT_KEY_AUTHTYPE "authtype"
#define NM_OPENCONNECT_KEY_USERCERT "usercert"
#define NM_OPENCONNECT_KEY_CACERT "cacert"
#define NM_OPENCONNECT_KEY_PRIVKEY "userkey"
#define NM_OPENCONNECT_KEY_USERNAME "username"
#define NM_OPENCONNECT_KEY_XMLCONFIG "xmlconfig"
#define NM_OPENCONNECT_KEY_CERTSIGS "certsigs"
#define NM_OPENCONNECT_KEY_LASTHOST "lasthost"
#define NM_OPENCONNECT_KEY_MTU "mtu"
#define NM_OPENCONNECT_KEY_AUTOCONNECT "autoconnect"

#define NM_OPENCONNECT_AUTHTYPE_CERT "cert"
#define NM_OPENCONNECT_AUTHTYPE_CERT_TPM "cert-tpm"
#define NM_OPENCONNECT_AUTHTYPE_PASSWORD "password"

typedef struct {
	NMVPNPlugin parent;
} NMOPENCONNECTPlugin;

typedef struct {
	NMVPNPluginClass parent;
} NMOPENCONNECTPluginClass;

GType nm_openconnect_plugin_get_type (void);

NMOPENCONNECTPlugin *nm_openconnect_plugin_new (void);

#define NM_OPENCONNECT_USER "nm-openconnect"

#endif /* NM_OPENCONNECT_PLUGIN_H */
