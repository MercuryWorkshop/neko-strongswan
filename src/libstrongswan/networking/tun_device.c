/*
 * Copyright (C) 2012-2014 Tobias Brunner
 * Copyright (C) 2012 Giuliano Grassi
 * Copyright (C) 2012 Ralf Sager
 * Copyright (C) 2012 Martin Willi
 *
 * Copyright (C) secunet Security Networks AG
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

#ifdef WIN32
/* Vista, for the iphlpapi.h address and interface functions */
#if !defined(_WIN32_WINNT) || _WIN32_WINNT < 0x0600
#undef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif
#include <winsock2.h>
#include <ws2ipdef.h>
#include <windows.h>
#include <iphlpapi.h>
#endif

#include "tun_device.h"

#include <utils/debug.h>
#include <threading/thread.h>

#if defined(__APPLE__)
#include "TargetConditionals.h"
#if !TARGET_OS_OSX
#define TUN_DEVICE_NOT_SUPPORTED
#endif
#elif !defined(__linux__) && !defined(HAVE_NET_IF_TUN_H) && !defined(WIN32)
#define TUN_DEVICE_NOT_SUPPORTED
#endif

#ifdef TUN_DEVICE_NOT_SUPPORTED

tun_device_t *tun_device_create(const char *name_tmpl)
{
	DBG1(DBG_LIB, "TUN devices are not supported");
	return NULL;
}

#elif defined(WIN32)

/*
 * Windows has no TUN driver of its own, this uses Wintun
 * (https://www.wintun.net), loaded at runtime from wintun.dll next to the
 * executable or in System32. Only the few functions used here are declared,
 * see wintun.h for their documentation.
 */

typedef void *WINTUN_ADAPTER_HANDLE;
typedef void *WINTUN_SESSION_HANDLE;

typedef WINTUN_ADAPTER_HANDLE (WINAPI *WINTUN_CREATE_ADAPTER_FUNC)
	(LPCWSTR name, LPCWSTR tunnel_type, const GUID *guid);
typedef WINTUN_ADAPTER_HANDLE (WINAPI *WINTUN_OPEN_ADAPTER_FUNC)(LPCWSTR name);
typedef void (WINAPI *WINTUN_CLOSE_ADAPTER_FUNC)(WINTUN_ADAPTER_HANDLE adapter);
typedef void (WINAPI *WINTUN_GET_ADAPTER_LUID_FUNC)
	(WINTUN_ADAPTER_HANDLE adapter, NET_LUID *luid);
typedef WINTUN_SESSION_HANDLE (WINAPI *WINTUN_START_SESSION_FUNC)
	(WINTUN_ADAPTER_HANDLE adapter, DWORD capacity);
typedef void (WINAPI *WINTUN_END_SESSION_FUNC)(WINTUN_SESSION_HANDLE session);
typedef HANDLE (WINAPI *WINTUN_GET_READ_WAIT_EVENT_FUNC)
	(WINTUN_SESSION_HANDLE session);
typedef BYTE* (WINAPI *WINTUN_RECEIVE_PACKET_FUNC)
	(WINTUN_SESSION_HANDLE session, DWORD *size);
typedef void (WINAPI *WINTUN_RELEASE_RECEIVE_PACKET_FUNC)
	(WINTUN_SESSION_HANDLE session, const BYTE *packet);
typedef BYTE* (WINAPI *WINTUN_ALLOCATE_SEND_PACKET_FUNC)
	(WINTUN_SESSION_HANDLE session, DWORD size);
typedef void (WINAPI *WINTUN_SEND_PACKET_FUNC)
	(WINTUN_SESSION_HANDLE session, const BYTE *packet);

/**
 * Ring buffer size per direction, a power of two between 128 KiB and 64 MiB
 */
#define WINTUN_RING_CAPACITY 0x400000

#define TUN_DEFAULT_MTU 1500

/**
 * Longest interface name we accept, Windows allows 255 characters
 */
#define TUN_NAME_LEN 128

typedef struct private_tun_device_t private_tun_device_t;

struct private_tun_device_t {

	/**
	 * Public interface
	 */
	tun_device_t public;

	/**
	 * wintun.dll
	 */
	HMODULE dll;

	/**
	 * Functions resolved from wintun.dll
	 */
	struct {
		WINTUN_CREATE_ADAPTER_FUNC create_adapter;
		WINTUN_OPEN_ADAPTER_FUNC open_adapter;
		WINTUN_CLOSE_ADAPTER_FUNC close_adapter;
		WINTUN_GET_ADAPTER_LUID_FUNC get_adapter_luid;
		WINTUN_START_SESSION_FUNC start_session;
		WINTUN_END_SESSION_FUNC end_session;
		WINTUN_GET_READ_WAIT_EVENT_FUNC get_read_wait_event;
		WINTUN_RECEIVE_PACKET_FUNC receive_packet;
		WINTUN_RELEASE_RECEIVE_PACKET_FUNC release_receive_packet;
		WINTUN_ALLOCATE_SEND_PACKET_FUNC allocate_send_packet;
		WINTUN_SEND_PACKET_FUNC send_packet;
	} wt;

	/**
	 * The Wintun adapter
	 */
	WINTUN_ADAPTER_HANDLE adapter;

	/**
	 * Packet session on the adapter
	 */
	WINTUN_SESSION_HANDLE session;

	/**
	 * Signaled when packets are ready to be received, owned by the session
	 */
	HANDLE read_event;

	/**
	 * LUID of the adapter, for the IP Helper API
	 */
	NET_LUID luid;

	/**
	 * Name of the adapter (its alias, as shown by ipconfig and netsh)
	 */
	char if_name[TUN_NAME_LEN];

	/**
	 * The current MTU
	 */
	int mtu;

	/**
	 * Associated address
	 */
	host_t *address;

	/**
	 * Netmask for address
	 */
	uint8_t netmask;
};

METHOD(tun_device_t, set_address, bool,
	private_tun_device_t *this, host_t *addr, uint8_t netmask)
{
	MIB_UNICASTIPADDRESS_ROW row;
	DWORD err;

	InitializeUnicastIpAddressEntry(&row);
	row.InterfaceLuid = this->luid;
	memcpy(&row.Address, addr->get_sockaddr(addr),
		   *addr->get_sockaddr_len(addr));
	row.OnLinkPrefixLength = netmask;
	row.DadState = IpDadStatePreferred;

	err = CreateUnicastIpAddressEntry(&row);
	if (err != NO_ERROR && err != ERROR_OBJECT_ALREADY_EXISTS)
	{
		DBG1(DBG_LIB, "failed to set address on %s: %lu", this->if_name, err);
		return FALSE;
	}
	DESTROY_IF(this->address);
	this->address = addr->clone(addr);
	this->netmask = netmask;
	return TRUE;
}

METHOD(tun_device_t, get_address, host_t*,
	private_tun_device_t *this, uint8_t *netmask)
{
	if (netmask && this->address)
	{
		*netmask = this->netmask;
	}
	return this->address;
}

METHOD(tun_device_t, up, bool,
	private_tun_device_t *this)
{
	/* a Wintun adapter is up while there is a session on it */
	return TRUE;
}

/**
 * Set the MTU of one IP version of the adapter
 */
static bool set_mtu_family(private_tun_device_t *this, int family, int mtu)
{
	MIB_IPINTERFACE_ROW row;
	DWORD err;

	InitializeIpInterfaceEntry(&row);
	row.Family = family;
	row.InterfaceLuid = this->luid;
	err = GetIpInterfaceEntry(&row);
	if (err == ERROR_NOT_FOUND)
	{	/* that IP version is disabled on the adapter */
		return TRUE;
	}
	if (err == NO_ERROR)
	{
		row.NlMtu = mtu;
		/* SitePrefixLength must be 0 for IPv4 or SetIpInterfaceEntry() fails */
		if (family == AF_INET)
		{
			row.SitePrefixLength = 0;
		}
		err = SetIpInterfaceEntry(&row);
	}
	if (err != NO_ERROR)
	{
		DBG1(DBG_LIB, "failed to set IPv%d MTU on %s: %lu",
			 family == AF_INET ? 4 : 6, this->if_name, err);
		return FALSE;
	}
	return TRUE;
}

METHOD(tun_device_t, set_mtu, bool,
	private_tun_device_t *this, int mtu)
{
	/* IPv6 needs at least 1280, it's disabled on the adapter below that */
	if (!set_mtu_family(this, AF_INET, mtu) ||
		(mtu >= 1280 && !set_mtu_family(this, AF_INET6, mtu)))
	{
		return FALSE;
	}
	this->mtu = mtu;
	return TRUE;
}

METHOD(tun_device_t, get_mtu, int,
	private_tun_device_t *this)
{
	return this->mtu > 0 ? this->mtu : TUN_DEFAULT_MTU;
}

METHOD(tun_device_t, get_name, char*,
	private_tun_device_t *this)
{
	return this->if_name;
}

METHOD(tun_device_t, get_fd, int,
	private_tun_device_t *this)
{
	/* there is no file descriptor, read_packet() blocks instead */
	return -1;
}

METHOD(tun_device_t, write_packet, bool,
	private_tun_device_t *this, chunk_t packet)
{
	BYTE *buf;

	buf = this->wt.allocate_send_packet(this->session, packet.len);
	if (!buf)
	{
		DBG1(DBG_LIB, "failed to write packet to TUN device %s: %lu",
			 this->if_name, GetLastError());
		return FALSE;
	}
	memcpy(buf, packet.ptr, packet.len);
	this->wt.send_packet(this->session, buf);
	return TRUE;
}

METHOD(tun_device_t, read_packet, bool,
	private_tun_device_t *this, chunk_t *packet)
{
	DWORD len, err;
	BYTE *buf;
	bool old;

	while (TRUE)
	{
		buf = this->wt.receive_packet(this->session, &len);
		if (buf)
		{
			*packet = chunk_clone(chunk_create(buf, len));
			this->wt.release_receive_packet(this->session, buf);
			return TRUE;
		}
		err = GetLastError();
		if (err != ERROR_NO_MORE_ITEMS)
		{	/* ERROR_HANDLE_EOF if the adapter went away */
			DBG1(DBG_LIB, "reading from TUN device %s failed: %lu",
				 this->if_name, err);
			return FALSE;
		}
		/* thread_cancel() queues an APC, which an alertable wait runs */
		old = thread_cancelability(TRUE);
		WaitForSingleObjectEx(this->read_event, INFINITE, TRUE);
		thread_cancelability(old);
	}
}

METHOD(tun_device_t, destroy, void,
	private_tun_device_t *this)
{
	if (this->session)
	{
		this->wt.end_session(this->session);
	}
	if (this->adapter)
	{	/* removes the adapter if we created it */
		this->wt.close_adapter(this->adapter);
	}
	if (this->dll)
	{
		FreeLibrary(this->dll);
	}
	DESTROY_IF(this->address);
	free(this);
}

/**
 * Load wintun.dll and resolve its functions
 */
static bool load_wintun(private_tun_device_t *this)
{
	struct {
		const char *name;
		FARPROC *func;
	} funcs[] = {
		{ "WintunCreateAdapter", (FARPROC*)&this->wt.create_adapter },
		{ "WintunOpenAdapter", (FARPROC*)&this->wt.open_adapter },
		{ "WintunCloseAdapter", (FARPROC*)&this->wt.close_adapter },
		{ "WintunGetAdapterLUID", (FARPROC*)&this->wt.get_adapter_luid },
		{ "WintunStartSession", (FARPROC*)&this->wt.start_session },
		{ "WintunEndSession", (FARPROC*)&this->wt.end_session },
		{ "WintunGetReadWaitEvent", (FARPROC*)&this->wt.get_read_wait_event },
		{ "WintunReceivePacket", (FARPROC*)&this->wt.receive_packet },
		{ "WintunReleaseReceivePacket",
								(FARPROC*)&this->wt.release_receive_packet },
		{ "WintunAllocateSendPacket", (FARPROC*)&this->wt.allocate_send_packet },
		{ "WintunSendPacket", (FARPROC*)&this->wt.send_packet },
	};
	int i;

	/* not the working directory or PATH, the DLL loads a kernel driver */
	this->dll = LoadLibraryExA("wintun.dll", NULL,
							   LOAD_LIBRARY_SEARCH_APPLICATION_DIR |
							   LOAD_LIBRARY_SEARCH_SYSTEM32);
	if (!this->dll)
	{
		DBG1(DBG_LIB, "failed to load wintun.dll (%lu), it has to be next to "
			 "the executable or in System32", GetLastError());
		return FALSE;
	}
	for (i = 0; i < countof(funcs); i++)
	{
		*funcs[i].func = GetProcAddress(this->dll, funcs[i].name);
		if (!*funcs[i].func)
		{
			DBG1(DBG_LIB, "wintun.dll has no %s", funcs[i].name);
			return FALSE;
		}
	}
	return TRUE;
}

/**
 * The same GUID for the same name on every run, so Windows sees the same
 * network (firewall profile, settings) instead of a new one each time
 */
static void name_guid(const char *name, GUID *guid)
{
	uint32_t h[4];
	chunk_t chunk = chunk_from_str((char*)name);
	int i;

	h[0] = chunk_hash_static_inc(chunk, 0x4e4b4f00);
	for (i = 1; i < countof(h); i++)
	{
		h[i] = chunk_hash_static_inc(chunk, h[i-1]);
	}
	memcpy(guid, h, sizeof(*guid));
	/* RFC 4122 version 4 (random) layout */
	guid->Data3 = (guid->Data3 & 0x0fff) | 0x4000;
	guid->Data4[0] = (guid->Data4[0] & 0x3f) | 0x80;
}

/**
 * Create the Wintun adapter and start a session on it
 */
static bool init_tun(private_tun_device_t *this, const char *name_tmpl)
{
	wchar_t wname[TUN_NAME_LEN];
	char *pos;
	GUID guid;
	DWORD err;

	/* "ipsec%d" and the like, there is only ever one of ours */
	strncpy(this->if_name, name_tmpl ?: "tun%d", sizeof(this->if_name) - 2);
	pos = strstr(this->if_name, "%d");
	if (pos)
	{
		pos[0] = '0';
		memmove(pos + 1, pos + 2, strlen(pos + 2) + 1);
	}
	if (!MultiByteToWideChar(CP_UTF8, 0, this->if_name, -1, wname,
							 countof(wname)))
	{
		DBG1(DBG_LIB, "invalid TUN device name %s", this->if_name);
		return FALSE;
	}
	if (!load_wintun(this))
	{
		return FALSE;
	}

	/* left behind by a previous run that didn't exit cleanly */
	this->adapter = this->wt.open_adapter(wname);
	if (this->adapter)
	{
		DBG1(DBG_LIB, "reusing existing Wintun adapter %s", this->if_name);
	}
	else
	{
		name_guid(this->if_name, &guid);
		this->adapter = this->wt.create_adapter(wname, L"strongSwan", &guid);
	}
	if (!this->adapter)
	{
		DBG1(DBG_LIB, "failed to create Wintun adapter %s: %lu",
			 this->if_name, GetLastError());
		return FALSE;
	}
	this->wt.get_adapter_luid(this->adapter, &this->luid);

	this->session = this->wt.start_session(this->adapter,
										   WINTUN_RING_CAPACITY);
	if (!this->session)
	{
		err = GetLastError();
		DBG1(DBG_LIB, "failed to start a session on Wintun adapter %s: %lu%s",
			 this->if_name, err, err == ERROR_ALREADY_EXISTS ?
			 " (in use by another process?)" : "");
		return FALSE;
	}
	this->read_event = this->wt.get_read_wait_event(this->session);
	return TRUE;
}

/*
 * Described in header
 */
tun_device_t *tun_device_create(const char *name_tmpl)
{
	private_tun_device_t *this;

	INIT(this,
		.public = {
			.read_packet = _read_packet,
			.write_packet = _write_packet,
			.get_mtu = _get_mtu,
			.set_mtu = _set_mtu,
			.get_name = _get_name,
			.get_fd = _get_fd,
			.set_address = _set_address,
			.get_address = _get_address,
			.up = _up,
			.destroy = _destroy,
		},
	);

	if (!init_tun(this, name_tmpl))
	{
		destroy(this);
		return NULL;
	}
	DBG1(DBG_LIB, "created TUN device: %s", this->if_name);
	return &this->public;
}

#else /* TUN devices supported */

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include <net/if.h>

#ifdef __APPLE__
#include <net/if_utun.h>
#include <netinet/in_var.h>
#include <sys/kern_control.h>
#elif defined(__linux__)
#include <linux/types.h>
#include <linux/if_tun.h>
#include <linux/ipv6.h>
#else
#include <net/if_tun.h>
#include <net/if_var.h>
#include <netinet/in_var.h>
#endif

#define TUN_DEFAULT_MTU 1500

typedef struct private_tun_device_t private_tun_device_t;

struct private_tun_device_t {

	/**
	 * Public interface
	 */
	tun_device_t public;

	/**
	 * The TUN device's file descriptor
	 */
	int tunfd;

	/**
	 * Name of the TUN device
	 */
	char if_name[IFNAMSIZ];

	/**
	 * Socket used for ioctl() to set interface addr, ...
	 */
	int sock;

	/**
	 * Socket used for ioctl() to set IPv6 interface addr, ...
	 */
	int sock_v6;

	/**
	 * The current MTU
	 */
	int mtu;

	/**
	 * Associated address
	 */
	host_t *address;

	/**
	 * Netmask for address
	 */
	uint8_t netmask;
};

#ifdef __linux__

/**
 * Set an IPv4 address and netmask
 */
static bool set_address_v4(private_tun_device_t *this, host_t *addr,
						   uint8_t netmask)
{
	struct ifreq ifr = {0};
	host_t *mask;

	strncpy(ifr.ifr_name, this->if_name, IFNAMSIZ);
	memcpy(&ifr.ifr_addr, addr->get_sockaddr(addr),
		   *addr->get_sockaddr_len(addr));

	if (ioctl(this->sock, SIOCSIFADDR, &ifr) < 0)
	{
		DBG1(DBG_LIB, "failed to set address on %s: %s",
			 this->if_name, strerror(errno));
		return FALSE;
	}
	mask = host_create_netmask(addr->get_family(addr), netmask);
	if (!mask)
	{
		DBG1(DBG_LIB, "invalid netmask: %d", netmask);
		return FALSE;
	}
	memcpy(&ifr.ifr_addr, mask->get_sockaddr(mask),
		   *mask->get_sockaddr_len(mask));
	mask->destroy(mask);

	if (ioctl(this->sock, SIOCSIFNETMASK, &ifr) < 0)
	{
		DBG1(DBG_LIB, "failed to set netmask on %s: %s",
			 this->if_name, strerror(errno));
		return FALSE;
	}
	return TRUE;
}

/**
 * Set an IPv6 address and netmask
 */
static bool set_address_v6(private_tun_device_t *this, host_t *addr,
						   uint8_t netmask)
{
	struct sockaddr_in6 *sin6;
	struct in6_ifreq ifr6 = {0};
	struct ifreq ifr = {0};

	strncpy(ifr.ifr_name, this->if_name, IFNAMSIZ);
	if (ioctl(this->sock_v6, SIOCGIFINDEX, &ifr) < 0)
	{
		DBG1(DBG_LIB, "failed to determine index of %s: %s",
			 this->if_name, strerror(errno));
		return FALSE;
	}

	sin6 = (struct sockaddr_in6*)addr->get_sockaddr(addr);
	memcpy(&ifr6.ifr6_addr, &sin6->sin6_addr, sizeof(ifr6.ifr6_addr));
	ifr6.ifr6_prefixlen = netmask;
	ifr6.ifr6_ifindex = ifr.ifr_ifindex;
	if (ioctl(this->sock_v6, SIOCSIFADDR, &ifr6) < 0)
	{
		DBG1(DBG_LIB, "failed to set address on %s: %s",
			 this->if_name, strerror(errno));
		return FALSE;
	}
	return TRUE;
}

#else /* __linux__ */

/**
 * Apply address and mask for IPv4
 */
static bool set_address_and_mask_v4(struct in_aliasreq *ifra, host_t *addr,
									uint8_t netmask)
{
	host_t *mask;

	memcpy(&ifra->ifra_addr, addr->get_sockaddr(addr),
		   *addr->get_sockaddr_len(addr));
	/* set the same address as destination address */
	memcpy(&ifra->ifra_dstaddr, addr->get_sockaddr(addr),
		   *addr->get_sockaddr_len(addr));

	mask = host_create_netmask(addr->get_family(addr), netmask);
	if (!mask)
	{
		DBG1(DBG_LIB, "invalid netmask: %d", netmask);
		return FALSE;
	}
	memcpy(&ifra->ifra_mask, mask->get_sockaddr(mask),
		   *mask->get_sockaddr_len(mask));
	mask->destroy(mask);
	return TRUE;
}

/**
 * Set the address for IPv4
 */
static bool set_address_v4(private_tun_device_t *this, host_t *addr,
						   uint8_t netmask)
{
	struct in_aliasreq ifra = {0};

	strncpy(ifra.ifra_name, this->if_name, IFNAMSIZ);

	if (this->address)
	{	/* remove the existing address first */
		if (!set_address_and_mask_v4(&ifra, this->address, this->netmask))
		{
			return FALSE;
		}
		if (ioctl(this->sock, SIOCDIFADDR, &ifra) < 0)
		{
			DBG1(DBG_LIB, "failed to remove existing address on %s: %s",
				 this->if_name, strerror(errno));
			return FALSE;
		}
	}
	if (!set_address_and_mask_v4(&ifra, addr, netmask))
	{
		return FALSE;
	}
	if (ioctl(this->sock, SIOCAIFADDR, &ifra) < 0)
	{
		DBG1(DBG_LIB, "failed to add address on %s: %s",
			 this->if_name, strerror(errno));
		return FALSE;
	}
	return TRUE;
}

/**
 * Apply address and mask for IPv6
 */
static bool set_address_and_mask_v6(struct in6_aliasreq *ifra, host_t *addr,
									uint8_t netmask)
{
	host_t *mask;

	memcpy(&ifra->ifra_addr, addr->get_sockaddr(addr),
		   *addr->get_sockaddr_len(addr));
	/* set the same address as destination address */
	memcpy(&ifra->ifra_dstaddr, addr->get_sockaddr(addr),
		   *addr->get_sockaddr_len(addr));

	mask = host_create_netmask(addr->get_family(addr), netmask);
	if (!mask)
	{
		DBG1(DBG_LIB, "invalid netmask: %d", netmask);
		return FALSE;
	}
	memcpy(&ifra->ifra_prefixmask, mask->get_sockaddr(mask),
		   *mask->get_sockaddr_len(mask));
	mask->destroy(mask);
	return TRUE;
}

/**
 * Set the address for IPv6
 */
static bool set_address_v6(private_tun_device_t *this, host_t *addr,
						   uint8_t netmask)
{
	struct in6_aliasreq ifra = {
		.ifra_lifetime = { 0, 0, 0xffffffff, 0xffffffff },
	};

	strncpy(ifra.ifra_name, this->if_name, IFNAMSIZ);

	if (this->address)
	{	/* remove the existing address first */
		if (!set_address_and_mask_v6(&ifra, this->address, this->netmask))
		{
			return FALSE;
		}
		if (ioctl(this->sock_v6, SIOCDIFADDR_IN6, &ifra) < 0)
		{
			DBG1(DBG_LIB, "failed to remove existing address on %s: %s",
				 this->if_name, strerror(errno));
			return FALSE;
		}
	}
	if (!set_address_and_mask_v6(&ifra, addr, netmask))
	{
		return FALSE;
	}
	if (ioctl(this->sock_v6, SIOCAIFADDR_IN6, &ifra) < 0)
	{
		DBG1(DBG_LIB, "failed to add address on %s: %s",
			 this->if_name, strerror(errno));
		return FALSE;
	}
	return TRUE;
}

#endif /* __linux__ */

METHOD(tun_device_t, set_address, bool,
	private_tun_device_t *this, host_t *addr, uint8_t netmask)
{
	switch (addr->get_family(addr))
	{
		case AF_INET:
			if (!set_address_v4(this, addr, netmask))
			{
				return FALSE;
			}
			break;
		case AF_INET6:
			if (!set_address_v6(this, addr, netmask))
			{
				return FALSE;
			}
			break;
		default:
			return FALSE;
	}
	DESTROY_IF(this->address);
	this->address = addr->clone(addr);
	this->netmask = netmask;
	return TRUE;
}

METHOD(tun_device_t, get_address, host_t*,
	private_tun_device_t *this, uint8_t *netmask)
{
	if (netmask && this->address)
	{
		*netmask = this->netmask;
	}
	return this->address;
}

METHOD(tun_device_t, up, bool,
	private_tun_device_t *this)
{
	struct ifreq ifr = {0};

	strncpy(ifr.ifr_name, this->if_name, IFNAMSIZ);

	if (ioctl(this->sock, SIOCGIFFLAGS, &ifr) < 0)
	{
		DBG1(DBG_LIB, "failed to get interface flags for %s: %s", this->if_name,
			 strerror(errno));
		return FALSE;
	}

	ifr.ifr_flags |= IFF_RUNNING | IFF_UP;

	if (ioctl(this->sock, SIOCSIFFLAGS, &ifr) < 0)
	{
		DBG1(DBG_LIB, "failed to set interface flags on %s: %s", this->if_name,
			 strerror(errno));
		return FALSE;
	}
	return TRUE;
}

METHOD(tun_device_t, set_mtu, bool,
	private_tun_device_t *this, int mtu)
{
	struct ifreq ifr = {0};

	strncpy(ifr.ifr_name, this->if_name, IFNAMSIZ);
	ifr.ifr_mtu = mtu;

	if (ioctl(this->sock, SIOCSIFMTU, &ifr) < 0)
	{
		DBG1(DBG_LIB, "failed to set MTU on %s: %s", this->if_name,
			 strerror(errno));
		return FALSE;
	}
	this->mtu = mtu;
	return TRUE;
}

METHOD(tun_device_t, get_mtu, int,
	private_tun_device_t *this)
{
	struct ifreq ifr = {0};

	if (this->mtu > 0)
	{
		return this->mtu;
	}

	strncpy(ifr.ifr_name, this->if_name, IFNAMSIZ);
	this->mtu = TUN_DEFAULT_MTU;

	if (ioctl(this->sock, SIOCGIFMTU, &ifr) == 0)
	{
		this->mtu = ifr.ifr_mtu;
	}
	return this->mtu;
}

METHOD(tun_device_t, get_name, char*,
	private_tun_device_t *this)
{
	return this->if_name;
}

METHOD(tun_device_t, get_fd, int,
	private_tun_device_t *this)
{
	return this->tunfd;
}

METHOD(tun_device_t, write_packet, bool,
	private_tun_device_t *this, chunk_t packet)
{
	ssize_t s;

#ifdef __APPLE__
	/* UTUN's expect the packets to be prepended by a 32-bit protocol number
	 * instead of parsing the packet again, we assume IPv4 for now */
	uint32_t proto = htonl(AF_INET);
	packet = chunk_cata("cc", chunk_from_thing(proto), packet);
#endif
	s = write(this->tunfd, packet.ptr, packet.len);
	if (s < 0)
	{
		DBG1(DBG_LIB, "failed to write packet to TUN device %s: %s",
			 this->if_name, strerror(errno));
		return FALSE;
	}
	else if (s != packet.len)
	{
		return FALSE;
	}
	return TRUE;
}

METHOD(tun_device_t, read_packet, bool,
	private_tun_device_t *this, chunk_t *packet)
{
	chunk_t data;
	ssize_t len;
	bool old;

	data = chunk_alloca(get_mtu(this));

	old = thread_cancelability(TRUE);
	len = read(this->tunfd, data.ptr, data.len);
	thread_cancelability(old);
	if (len < 0)
	{
		DBG1(DBG_LIB, "reading from TUN device %s failed: %s", this->if_name,
			 strerror(errno));
		return FALSE;
	}
	data.len = len;
#ifdef __APPLE__
	/* UTUN's prepend packets with a 32-bit protocol number */
	data = chunk_skip(data, sizeof(uint32_t));
#endif
	*packet = chunk_clone(data);
	return TRUE;
}

METHOD(tun_device_t, destroy, void,
	private_tun_device_t *this)
{
	if (this->tunfd > 0)
	{
		close(this->tunfd);
#ifdef __FreeBSD__
		/* tun(4) says the following: "These network interfaces persist until
		 * the if_tun.ko module is unloaded, or until removed with the
		 * ifconfig(8) command."  So simply closing the FD is not enough. */
		struct ifreq ifr = {0};

		strncpy(ifr.ifr_name, this->if_name, IFNAMSIZ);
		if (ioctl(this->sock, SIOCIFDESTROY, &ifr) < 0)
		{
			DBG1(DBG_LIB, "failed to destroy %s: %s", this->if_name,
				 strerror(errno));
		}
#endif /* __FreeBSD__ */
	}
	if (this->sock > 0)
	{
		close(this->sock);
	}
	if (this->sock_v6 > 0)
	{
		close(this->sock_v6);
	}
	DESTROY_IF(this->address);
	free(this);
}

/**
 * Initialize the tun device
 */
static bool init_tun(private_tun_device_t *this, const char *name_tmpl)
{
#ifdef __APPLE__

	struct ctl_info info = {0};
	struct sockaddr_ctl addr = {0};
	socklen_t size = IFNAMSIZ;

	this->tunfd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
	if (this->tunfd < 0)
	{
		DBG1(DBG_LIB, "failed to open tundevice PF_SYSTEM socket: %s",
			 strerror(errno));
		return FALSE;
	}

	/* get a control identifier for the utun kernel extension */
	strncpy(info.ctl_name, UTUN_CONTROL_NAME, sizeof(info.ctl_name)-1);
	if (ioctl(this->tunfd, CTLIOCGINFO, &info) < 0)
	{
		DBG1(DBG_LIB, "failed to ioctl tundevice: %s", strerror(errno));
		close(this->tunfd);
		return FALSE;
	}

	addr.sc_id = info.ctl_id;
	addr.sc_len = sizeof(addr);
	addr.sc_family = AF_SYSTEM;
	addr.ss_sysaddr = AF_SYS_CONTROL;
	/* allocate identifier dynamically */
	addr.sc_unit = 0;

	if (connect(this->tunfd, (struct sockaddr*)&addr, sizeof(addr)) < 0)
	{
		DBG1(DBG_LIB, "failed to connect tundevice: %s", strerror(errno));
		close(this->tunfd);
		return FALSE;
	}
	if (getsockopt(this->tunfd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME,
				   this->if_name, &size) < 0)
	{
		DBG1(DBG_LIB, "getting tundevice name failed: %s", strerror(errno));
		close(this->tunfd);
		return FALSE;
	}
	return TRUE;

#elif defined(IFF_TUN)

	struct ifreq ifr = {0};

	strncpy(this->if_name, name_tmpl ?: "tun%d", IFNAMSIZ-1);
	this->if_name[IFNAMSIZ-1] = '\0';

	this->tunfd = open("/dev/net/tun", O_RDWR);
	if (this->tunfd < 0)
	{
		DBG1(DBG_LIB, "failed to open /dev/net/tun: %s", strerror(errno));
		return FALSE;
	}

	/* TUN device, no packet info */
	ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

	strncpy(ifr.ifr_name, this->if_name, IFNAMSIZ);
	if (ioctl(this->tunfd, TUNSETIFF, (void*)&ifr) < 0)
	{
		DBG1(DBG_LIB, "failed to configure TUN device: %s", strerror(errno));
		close(this->tunfd);
		return FALSE;
	}
	strncpy(this->if_name, ifr.ifr_name, IFNAMSIZ);
	return TRUE;

#elif defined(__FreeBSD__)

	if (name_tmpl)
	{
		DBG1(DBG_LIB, "arbitrary naming of TUN devices is not supported");
	}

	this->tunfd = open("/dev/tun", O_RDWR);
	if (this->tunfd < 0)
	{
		DBG1(DBG_LIB, "failed to open /dev/tun: %s", strerror(errno));
		return FALSE;
	}
	fdevname_r(this->tunfd, this->if_name, IFNAMSIZ);
	return TRUE;

#else /* !__FreeBSD__ */

	/* this might work on Linux with older TUN driver versions (no IFF_TUN) */
	char devname[IFNAMSIZ];
	/* the same process is allowed to open a device again, but that's not what
	 * we want (unless we previously closed a device, which we don't know at
	 * this point).  therefore, this counter is static so we don't accidentally
	 * open a device twice */
	static int i = -1;

	if (name_tmpl)
	{
		DBG1(DBG_LIB, "arbitrary naming of TUN devices is not supported");
	}

	for (; ++i < 256; )
	{
		snprintf(devname, IFNAMSIZ, "/dev/tun%d", i);
		this->tunfd = open(devname, O_RDWR);
		if (this->tunfd > 0)
		{	/* for ioctl(2) calls only the interface name is used */
			snprintf(this->if_name, IFNAMSIZ, "tun%d", i);
			break;
		}
		DBG1(DBG_LIB, "failed to open %s: %s", this->if_name, strerror(errno));
	}
	return this->tunfd > 0;

#endif /* !__APPLE__ */
}

/*
 * Described in header
 */
tun_device_t *tun_device_create(const char *name_tmpl)
{
	private_tun_device_t *this;

	INIT(this,
		.public = {
			.read_packet = _read_packet,
			.write_packet = _write_packet,
			.get_mtu = _get_mtu,
			.set_mtu = _set_mtu,
			.get_name = _get_name,
			.get_fd = _get_fd,
			.set_address = _set_address,
			.get_address = _get_address,
			.up = _up,
			.destroy = _destroy,
		},
		.tunfd = -1,
		.sock = -1,
		.sock_v6 = -1,
	);

	if (!init_tun(this, name_tmpl))
	{
		free(this);
		return NULL;
	}
	DBG1(DBG_LIB, "created TUN device: %s", this->if_name);

	this->sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (this->sock < 0)
	{
		DBG1(DBG_LIB, "failed to open socket to configure TUN device");
		destroy(this);
		return NULL;
	}
	/* FIXME: allow this to fail? (just ignore IPv6 addrs later?) */
	this->sock_v6 = socket(AF_INET6, SOCK_DGRAM, 0);
	if (this->sock_v6 < 0)
	{
		DBG1(DBG_LIB, "failed to open IPv6 socket to configure TUN device");
		destroy(this);
		return NULL;
	}
	return &this->public;
}

#endif /* TUN devices supported */
