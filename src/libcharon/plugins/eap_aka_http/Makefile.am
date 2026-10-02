AM_CPPFLAGS = \
	-I$(top_srcdir)/src/libstrongswan \
	-I$(top_srcdir)/src/libcharon \
	-I$(top_srcdir)/src/libsimaka

AM_CFLAGS = \
	$(PLUGIN_CFLAGS)

libstrongswan_eap_aka_http_la_LDFLAGS = -module -avoid-version

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-eap-aka-http.la
else
plugin_LTLIBRARIES = libstrongswan-eap-aka-http.la
libstrongswan_eap_aka_http_la_LIBADD = $(top_builddir)/src/libsimaka/libsimaka.la
endif

libstrongswan_eap_aka_http_la_SOURCES = \
	eap_aka_http_plugin.h eap_aka_http_plugin.c \
	eap_aka_http_card.h eap_aka_http_card.c
