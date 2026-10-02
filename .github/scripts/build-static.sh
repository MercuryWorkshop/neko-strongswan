#!/bin/sh
# Build a fully static, monolithic charon with the plugins the NekoIMS ePDG
# dialer needs (no OpenSSL; crypto from strongSwan's own plugins and a static
# GMP) and package it as a tar.gz.
#
#   .github/scripts/build-static.sh <version> [outdir]
#
# Meant for Alpine (musl), but works on any Linux with a static libc, a C
# toolchain, autotools, gperf, bison, flex, python3 and curl.
set -eu

VERSION=${1:?usage: $0 <version> [outdir]}
OUTDIR=${2:-dist}

GMP_VERSION=6.3.0
GMP_SHA256=a3c2b80201b89e68616f4ad30bc66aee4927c3ce50e33929ca819d5c43538898

SRC=$(pwd)
WORK=$SRC/build-static
GMP=$WORK/gmp
JOBS=$(nproc 2>/dev/null || echo 2)

case $(uname -m) in
	x86_64)			ARCH=x86_64 ;;
	aarch64|arm64)	ARCH=arm64 ;;
	*)				ARCH=$(uname -m) ;;
esac
NAME=strongswan-nekoims-$VERSION-linux-$ARCH

mkdir -p "$WORK" "$OUTDIR"

# -- GMP ---------------------------------------------------------------------

if [ ! -f "$GMP/lib/libgmp.a" ]; then
	cd "$WORK"
	curl -sSfLO "https://gmplib.org/download/gmp/gmp-$GMP_VERSION.tar.xz"
	echo "$GMP_SHA256  gmp-$GMP_VERSION.tar.xz" | sha256sum -c -
	tar xf "gmp-$GMP_VERSION.tar.xz"
	cd "gmp-$GMP_VERSION"
	./configure --prefix="$GMP" --disable-shared --enable-static --with-pic \
		CFLAGS="-O2 -std=gnu17"
	make -j"$JOBS"
	make install
fi

# -- charon ------------------------------------------------------------------

cd "$SRC"
./autogen.sh
./configure --prefix=/usr/local --sysconfdir=/etc \
	--disable-defaults --enable-monolithic --enable-static --disable-shared \
	--enable-ikev2 --enable-charon --enable-vici \
	--enable-random --enable-nonce --enable-drbg \
	--enable-aes --enable-sha1 --enable-sha2 --enable-hmac --enable-gmp \
	--enable-curve25519 --enable-fips-prf --enable-kdf \
	--enable-x509 --enable-pem --enable-pubkey --enable-pkcs1 \
	--enable-constraints \
	--enable-kernel-netlink --enable-socket-default \
	--enable-eap-identity --enable-eap-aka --enable-eap-aka-http \
	--enable-p-cscf \
	CPPFLAGS="-I$GMP/include" LDFLAGS="-L$GMP/lib"
# -all-static only at link time, configure's link tests can't use it
make -j"$JOBS" LDFLAGS="-L$GMP/lib -all-static"

CHARON=src/charon/charon
if readelf -l "$CHARON" | grep -q INTERP; then
	echo "error: $CHARON is dynamically linked" >&2
	exit 1
fi

# -- package -----------------------------------------------------------------

# Laid out like the /usr/local prefix charon was configured for, so
# extracting into /usr/local puts it where the dialer looks.
PKG=$WORK/$NAME
rm -rf "$PKG"
mkdir -p "$PKG/libexec/ipsec" "$PKG/lib/python" \
	"$PKG/share/doc/strongswan-nekoims"
cp "$CHARON" "$PKG/libexec/ipsec/charon"
strip "$PKG/libexec/ipsec/charon"
cp -R src/libcharon/plugins/vici/python/vici "$PKG/lib/python/vici"
find "$PKG/lib/python" -name '__pycache__' -prune -exec rm -rf {} +
cp COPYING LICENSE "$PKG/share/doc/strongswan-nekoims/"
cat > "$PKG/share/doc/strongswan-nekoims/README" <<EOF
strongSwan $VERSION (NekoIMS fork), static monolithic charon for linux-$ARCH.

  libexec/ipsec/charon   built-in plugins: $(sed -n 's/^charon_plugins = *//p' Makefile)
  lib/python/vici        strongSwan's vici Python client (pure Python)

charon reads its settings from \$STRONGSWAN_CONF. The NekoIMS dialer
(dialers/strongswan-dialer.py) generates that file and drives charon over
vici; pass --charon <path>/libexec/ipsec/charon and put lib/python on
PYTHONPATH, or extract this archive into /usr/local.
EOF

tar -C "$WORK" -czf "$OUTDIR/$NAME.tar.gz" "$NAME"
(cd "$OUTDIR" && sha256sum "$NAME.tar.gz" > "$NAME.tar.gz.sha256")
echo "built $OUTDIR/$NAME.tar.gz"
