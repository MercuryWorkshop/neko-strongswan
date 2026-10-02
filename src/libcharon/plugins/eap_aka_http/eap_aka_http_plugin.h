/*
 * Copyright (C) 2026 ProgrammerIn-wonderland
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

/**
 * @defgroup eap_aka_http eap_aka_http
 * @ingroup cplugins
 *
 * @defgroup eap_aka_http_plugin eap_aka_http_plugin
 * @{ @ingroup eap_aka_http
 */

#ifndef EAP_AKA_HTTP_PLUGIN_H_
#define EAP_AKA_HTTP_PLUGIN_H_

#include <plugins/plugin.h>

typedef struct eap_aka_http_plugin_t eap_aka_http_plugin_t;

/**
 * Plugin providing an AKA card backed by a USIM-https-server compatible
 * service, such as the NekoIMS simcard-server.
 */
struct eap_aka_http_plugin_t {

	/**
	 * implements plugin interface
	 */
	plugin_t plugin;
};

#endif /** EAP_AKA_HTTP_PLUGIN_H_ @}*/
