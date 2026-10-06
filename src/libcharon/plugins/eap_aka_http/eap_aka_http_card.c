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

#include "eap_aka_http_card.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#ifdef WIN32
/* AF_UNIX stream sockets, Windows 10 1803 and later */
#include <afunix.h>
#else
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#endif

#include <daemon.h>
#include <threading/mutex.h>

/**
 * Default server, the NekoIMS simcard-server socket
 */
#define DEFAULT_SERVER "unix:/run/nekoims/simcard.sock"

/**
 * Maximum size of a response we accept, all of them are tiny JSON objects
 */
#define MAX_RESPONSE 4096

typedef struct private_eap_aka_http_card_t private_eap_aka_http_card_t;

/**
 * Private data of an eap_aka_http_card_t object.
 */
struct private_eap_aka_http_card_t {

	/**
	 * Public eap_aka_http_card_t interface.
	 */
	eap_aka_http_card_t public;

	/**
	 * Unix socket path, NULL for TCP
	 */
	char *path;

	/**
	 * TCP host, NULL for a Unix socket
	 */
	char *host;

	/**
	 * TCP port
	 */
	uint16_t port;

	/**
	 * Path prefix of the HTTP request, "/" by default
	 */
	char *prefix;

	/**
	 * Send/receive timeout in seconds
	 */
	u_int timeout;

	/**
	 * RAND of the last synchronization failure
	 */
	char auts_rand[AKA_RAND_LEN];

	/**
	 * AUTS of the last synchronization failure
	 */
	char auts[AKA_AUTS_LEN];

	/**
	 * Whether auts/auts_rand are set
	 */
	bool have_auts;

	/**
	 * Protects the AUTS cache
	 */
	mutex_t *mutex;
};

/**
 * Parse "unix:/path" or "http://host[:port][/prefix]"
 */
static bool parse_server(private_eap_aka_http_card_t *this, char *server)
{
	char *pos, *end, *host;

	if (strpfx(server, "unix:"))
	{
		this->path = strdup(server + strlen("unix:"));
		this->prefix = strdup("/");
		return strlen(this->path) > 0;
	}
	if (!strpfx(server, "http://"))
	{
		return FALSE;
	}
	host = server + strlen("http://");
	end = strchr(host, '/');
	this->prefix = strdup(end ? end : "/");
	this->port = 80;
	if (*host == '[')
	{	/* [IPv6]:port */
		pos = strchr(host, ']');
		if (!pos || (end && pos > end))
		{
			return FALSE;
		}
		this->host = strndup(host + 1, pos - host - 1);
		pos++;
	}
	else
	{
		pos = host;
		while (*pos && *pos != ':' && *pos != '/')
		{
			pos++;
		}
		this->host = strndup(host, pos - host);
	}
	if (*pos == ':')
	{
		this->port = atoi(pos + 1);
	}
	return strlen(this->host) > 0 && this->port;
}

/**
 * Set the send/receive timeouts of a socket
 */
static void set_timeouts(private_eap_aka_http_card_t *this, int fd)
{
#ifdef WIN32
	/* milliseconds as a DWORD instead of a timeval */
	DWORD tv = this->timeout * 1000;
#else
	struct timeval tv = { .tv_sec = this->timeout };
#endif

	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

/**
 * Connect to the configured server, returns -1 on error
 */
static int connect_server(private_eap_aka_http_card_t *this)
{
	host_t *host = NULL;
	int fd;

	if (this->path)
	{
		struct sockaddr_un addr = { .sun_family = AF_UNIX };

		if (strlen(this->path) >= sizeof(addr.sun_path))
		{
			DBG1(DBG_IKE, "simcard server path too long");
			return -1;
		}
		strncpy(addr.sun_path, this->path, sizeof(addr.sun_path) - 1);
		fd = socket(AF_UNIX, SOCK_STREAM, 0);
		if (fd < 0)
		{
			return -1;
		}
		set_timeouts(this, fd);
		if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) == 0)
		{
			return fd;
		}
		DBG1(DBG_IKE, "connecting to simcard server %s failed: %s",
			 this->path, strerror(errno));
		close(fd);
		return -1;
	}

	host = host_create_from_dns(this->host, AF_UNSPEC, this->port);
	if (!host)
	{
		DBG1(DBG_IKE, "resolving simcard server %s failed", this->host);
		return -1;
	}
	fd = socket(host->get_family(host), SOCK_STREAM, 0);
	if (fd >= 0)
	{
		set_timeouts(this, fd);
		if (connect(fd, host->get_sockaddr(host),
					*host->get_sockaddr_len(host)) != 0)
		{
			DBG1(DBG_IKE, "connecting to simcard server %#H failed: %s",
				 host, strerror(errno));
			close(fd);
			fd = -1;
		}
	}
	host->destroy(host);
	return fd;
}

/**
 * Issue "GET <prefix>?<query>", returns the body of a 200 response in buf
 */
static bool http_get(private_eap_aka_http_card_t *this, char *query,
					 char *buf, size_t buflen)
{
	char req[512], *body;
	size_t len = 0;
	ssize_t n;
	int fd, code, reqlen;

	reqlen = snprintf(req, sizeof(req), "GET %s?%s HTTP/1.0\r\n"
					  "Host: %s\r\nConnection: close\r\n\r\n",
					  this->prefix, query, this->host ?: "simcard");
	if (reqlen < 0 || reqlen >= sizeof(req))
	{
		return FALSE;
	}
	fd = connect_server(this);
	if (fd < 0)
	{
		return FALSE;
	}
	if (send(fd, req, reqlen, 0) != reqlen)
	{
		DBG1(DBG_IKE, "sending to simcard server failed: %s", strerror(errno));
		close(fd);
		return FALSE;
	}
	while (len < buflen - 1)
	{
		n = recv(fd, buf + len, buflen - 1 - len, 0);
		if (n < 0 && errno == EINTR)
		{
			continue;
		}
		if (n <= 0)
		{
			break;
		}
		len += n;
	}
	close(fd);
	buf[len] = '\0';

	if (sscanf(buf, "HTTP/%*u.%*u %d", &code) != 1)
	{
		DBG1(DBG_IKE, "invalid response from simcard server");
		return FALSE;
	}
	body = strstr(buf, "\r\n\r\n");
	body = body ? body + 4 : buf + len;
	if (code != 200)
	{
		DBG1(DBG_IKE, "simcard server returned HTTP %d: %s", code, body);
		return FALSE;
	}
	memmove(buf, body, strlen(body) + 1);
	return TRUE;
}

/**
 * Extract the string value of "key" from a flat JSON object. Returns FALSE
 * if the key is missing or its value is not a string (e.g. null).
 */
static bool json_string(char *json, char *key, char *out, size_t outlen)
{
	char needle[32], *pos, *end;

	snprintf(needle, sizeof(needle), "\"%s\"", key);
	pos = strstr(json, needle);
	if (!pos)
	{
		return FALSE;
	}
	pos += strlen(needle);
	pos += strspn(pos, " \t\r\n");
	if (*pos++ != ':')
	{
		return FALSE;
	}
	pos += strspn(pos, " \t\r\n");
	if (*pos++ != '"')
	{
		return FALSE;
	}
	end = strchr(pos, '"');
	if (!end || end - pos >= outlen)
	{
		return FALSE;
	}
	memcpy(out, pos, end - pos);
	out[end - pos] = '\0';
	return TRUE;
}

/**
 * Decode the hex string value of "key" into buf, returns its length or -1
 */
static int json_hex(char *json, char *key, char *buf, size_t buflen)
{
	char hex[2 * AKA_RES_MAX + 1];
	chunk_t chunk;
	size_t len;

	if (!json_string(json, key, hex, sizeof(hex)))
	{
		return -1;
	}
	len = strlen(hex);
	if (len % 2 || len / 2 > buflen || strspn(hex, "0123456789abcdefABCDEF")
		!= len)
	{
		return -1;
	}
	chunk = chunk_from_hex(chunk_create(hex, len), buf);
	return chunk.len;
}

/**
 * Check that id is the permanent identity of the SIM behind the server, so
 * other cards get a chance for identities we don't serve
 */
static bool matches_imsi(private_eap_aka_http_card_t *this,
						 identification_t *id)
{
	char buf[MAX_RESPONSE], imsi[16], user[128], *at;

	if (!http_get(this, "type=imsi", buf, sizeof(buf)) ||
		!json_string(buf, "imsi", imsi, sizeof(imsi)))
	{
		return FALSE;
	}
	/* "0<IMSI>@nai.epc..." (TS 23.003 19.3.2), or the bare IMSI */
	snprintf(user, sizeof(user), "%Y", id);
	at = strchr(user, '@');
	if (at)
	{
		*at = '\0';
	}
	if (streq(user, imsi) || (user[0] == '0' && streq(user + 1, imsi)))
	{
		return TRUE;
	}
	DBG2(DBG_IKE, "simcard server IMSI %s does not match '%Y'", imsi, id);
	return FALSE;
}

METHOD(simaka_card_t, get_quintuplet, status_t,
	private_eap_aka_http_card_t *this, identification_t *id,
	char rand[AKA_RAND_LEN], char autn[AKA_AUTN_LEN], char ck[AKA_CK_LEN],
	char ik[AKA_IK_LEN], char res[AKA_RES_MAX], int *res_len)
{
	char query[128], buf[MAX_RESPONSE], auts[AKA_AUTS_LEN];
	chunk_t rand_chunk = chunk_create(rand, AKA_RAND_LEN);
	chunk_t autn_chunk = chunk_create(autn, AKA_AUTN_LEN);
	int len;

	if (!matches_imsi(this, id))
	{
		return FAILED;
	}
	snprintf(query, sizeof(query), "type=rand-autn&rand=%+B&autn=%+B",
			 &rand_chunk, &autn_chunk);
	if (!http_get(this, query, buf, sizeof(buf)))
	{
		return FAILED;
	}

	/* {"res": "<auts>", "ck": null, "ik": null, "auts": "<auts>"} */
	if (json_hex(buf, "auts", auts, sizeof(auts)) == AKA_AUTS_LEN)
	{
		DBG1(DBG_IKE, "USIM reported a sequence number synchronization "
			 "failure");
		this->mutex->lock(this->mutex);
		memcpy(this->auts_rand, rand, AKA_RAND_LEN);
		memcpy(this->auts, auts, AKA_AUTS_LEN);
		this->have_auts = TRUE;
		this->mutex->unlock(this->mutex);
		return INVALID_STATE;
	}

	len = json_hex(buf, "res", res, AKA_RES_MAX);
	if (len < 4 ||
		json_hex(buf, "ck", ck, AKA_CK_LEN) != AKA_CK_LEN ||
		json_hex(buf, "ik", ik, AKA_IK_LEN) != AKA_IK_LEN)
	{
		DBG1(DBG_IKE, "invalid AKA response from simcard server");
		return FAILED;
	}
	*res_len = len;
	DBG2(DBG_IKE, "got RES/CK/IK for '%Y' from simcard server", id);
	return SUCCESS;
}

METHOD(simaka_card_t, resync, bool,
	private_eap_aka_http_card_t *this, identification_t *id,
	char rand[AKA_RAND_LEN], char auts[AKA_AUTS_LEN])
{
	bool found = FALSE;

	this->mutex->lock(this->mutex);
	if (this->have_auts && memeq(this->auts_rand, rand, AKA_RAND_LEN))
	{
		memcpy(auts, this->auts, AKA_AUTS_LEN);
		this->have_auts = FALSE;
		found = TRUE;
	}
	this->mutex->unlock(this->mutex);
	return found;
}

METHOD(eap_aka_http_card_t, destroy, void,
	private_eap_aka_http_card_t *this)
{
	memwipe(this->auts, sizeof(this->auts));
	this->mutex->destroy(this->mutex);
	free(this->path);
	free(this->host);
	free(this->prefix);
	free(this);
}

/**
 * See header
 */
eap_aka_http_card_t *eap_aka_http_card_create()
{
	private_eap_aka_http_card_t *this;
	char *server;

	INIT(this,
		.public = {
			.card = {
				.get_triplet = (void*)return_false,
				.get_quintuplet = _get_quintuplet,
				.resync = _resync,
				.get_pseudonym = (void*)return_null,
				.set_pseudonym = (void*)nop,
				.get_reauth = (void*)return_null,
				.set_reauth = (void*)nop,
			},
			.destroy = _destroy,
		},
		.timeout = lib->settings->get_int(lib->settings,
						"%s.plugins.eap-aka-http.timeout", 5, lib->ns),
		.mutex = mutex_create(MUTEX_TYPE_DEFAULT),
	);

	server = lib->settings->get_str(lib->settings,
						"%s.plugins.eap-aka-http.server", DEFAULT_SERVER, lib->ns);
	if (!parse_server(this, server))
	{
		DBG1(DBG_CFG, "invalid eap-aka-http server '%s'", server);
		destroy(this);
		return NULL;
	}
	return &this->public;
}
