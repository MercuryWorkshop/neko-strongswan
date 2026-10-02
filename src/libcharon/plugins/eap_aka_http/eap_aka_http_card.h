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
 * @defgroup eap_aka_http_card eap_aka_http_card
 * @{ @ingroup eap_aka_http
 */

#ifndef EAP_AKA_HTTP_CARD_H_
#define EAP_AKA_HTTP_CARD_H_

#include <simaka_card.h>

typedef struct eap_aka_http_card_t eap_aka_http_card_t;

/**
 * USIM card implementation querying a USIM-https-server compatible HTTP
 * service, over a Unix socket or TCP.
 */
struct eap_aka_http_card_t {

	/**
	 * Implements simaka_card_t interface
	 */
	simaka_card_t card;

	/**
	 * Destroy a eap_aka_http_card_t.
	 */
	void (*destroy)(eap_aka_http_card_t *this);
};

/**
 * Create a eap_aka_http_card instance.
 *
 * @return			card, NULL if the configured server is invalid
 */
eap_aka_http_card_t *eap_aka_http_card_create();

#endif /** EAP_AKA_HTTP_CARD_H_ @}*/
