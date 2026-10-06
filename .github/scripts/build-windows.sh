#!/bin/sh
# Cross-compile a static, monolithic charon-svc.exe for Windows (x86_64 or
# arm64) with the plugins the NekoIMS ePDG dialer needs, and package it with
# Wintun as a zip.
#
#   .github/scripts/build-windows.sh <version> <x86_64|arm64> [outdir]
#
# Runs on Linux (x86_64 or aarch64) with autotools, bison, flex, python3,
# curl and unzip. gperf and the llvm-mingw toolchain are fetched into
# build-windows/ unless found ($LLVM_MINGW can point at an unpacked one).
#
# The data plane is kernel-libipsec on a Wintun adapter rather than the
# kernel IPsec stack (kernel-wfp): that needs IKEEXT out of the way, can't
# carry an IPv6 inner over an IPv4 outer, and gives no interface to bind to.
set -eu

VERSION=${1:?usage: $0 <version> <x86_64|arm64> [outdir]}
ARCH=${2:?usage: $0 <version> <x86_64|arm64> [outdir]}
OUTDIR=${3:-dist}

GMP_VERSION=6.3.0
GMP_SHA256=a3c2b80201b89e68616f4ad30bc66aee4927c3ce50e33929ca819d5c43538898
GPERF_VERSION=3.1
GPERF_SHA256=588546b945bba4b70b6a3a616e80b4ab466e3f33024a352fc2198112cdbb3ae2
LLVM_MINGW_VERSION=20250114
WINTUN_VERSION=0.14.1
WINTUN_SHA256=07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51

case $ARCH in
	x86_64)	TRIPLE=x86_64-w64-mingw32; WINTUN_ARCH=amd64 ;;
	arm64)	TRIPLE=aarch64-w64-mingw32; WINTUN_ARCH=arm64 ;;
	*)		echo "unknown arch $ARCH" >&2; exit 1 ;;
esac

# clang (llvm-mingw up to at least 20260922, LLVM 23.1.2) breaks the Windows
# arm64 variadic ABI for 16-byte structs: a chunk_t that starts in x7 is put
# entirely on the stack by the caller, while va_arg() (like MSVC) expects it
# split between x7 and the stack. chunk_length()/chunk_cat() and the
# credential builders then read garbage and charon crashes in its first
# IKE_SA_INIT (ike_natd.c). Use the x86_64 build on arm64, it runs emulated
# (Wintun's amd64 DLL included); the dialer picks it there.
if [ "$ARCH" = arm64 ] && [ -z "${NEKOIMS_ALLOW_ARM64:-}" ]; then
	echo "arm64 builds crash (clang struct varargs bug), use x86_64;" \
		"NEKOIMS_ALLOW_ARM64=1 to build anyway" >&2
	exit 1
fi

SRC=$(pwd)
WORK=$SRC/build-windows
TOOLS=$WORK/tools
DEPS=$WORK/$ARCH
JOBS=$(nproc 2>/dev/null || echo 2)
NAME=strongswan-nekoims-$VERSION-windows-$ARCH

mkdir -p "$WORK" "$TOOLS/bin" "$DEPS" "$OUTDIR"
OUTDIR=$(cd "$OUTDIR" && pwd)
export PATH="$TOOLS/bin:$PATH"

fetch() {	# url sha256 file
	[ -f "$WORK/$3" ] || curl -sSfL -o "$WORK/$3" "$1"
	echo "$2  $WORK/$3" | sha256sum -c - >/dev/null
}

# -- tools -------------------------------------------------------------------

if ! command -v gperf >/dev/null; then
	fetch "https://ftp.gnu.org/pub/gnu/gperf/gperf-$GPERF_VERSION.tar.gz" \
		"$GPERF_SHA256" gperf.tar.gz
	rm -rf "$WORK/gperf-$GPERF_VERSION"
	tar -C "$WORK" -xzf "$WORK/gperf.tar.gz"
	(cd "$WORK/gperf-$GPERF_VERSION" &&
		./configure --prefix="$TOOLS" CXXFLAGS="-O2 -std=gnu++11" >/dev/null &&
		make -j"$JOBS" >/dev/null && make install >/dev/null)
fi

if [ -z "${LLVM_MINGW:-}" ]; then
	case $(uname -m) in
		x86_64)			HOST=x86_64 ;;
		aarch64|arm64)	HOST=aarch64 ;;
		*)				echo "no llvm-mingw for $(uname -m)" >&2; exit 1 ;;
	esac
	LLVM_MINGW=$TOOLS/llvm-mingw-$LLVM_MINGW_VERSION-ucrt-ubuntu-20.04-$HOST
	if [ ! -d "$LLVM_MINGW" ]; then
		curl -sSfL "https://github.com/mstorsjo/llvm-mingw/releases/download/$LLVM_MINGW_VERSION/llvm-mingw-$LLVM_MINGW_VERSION-ucrt-ubuntu-20.04-$HOST.tar.xz" |
			tar -C "$TOOLS" -xJf -
	fi
fi
export PATH="$LLVM_MINGW/bin:$PATH"
CC=$TRIPLE-gcc
command -v "$CC" >/dev/null || { echo "$CC not found" >&2; exit 1; }

# -- GMP (DH groups) -----------------------------------------------------------

if [ ! -f "$DEPS/gmp/lib/libgmp.a" ]; then
	fetch "https://gmplib.org/download/gmp/gmp-$GMP_VERSION.tar.xz" \
		"$GMP_SHA256" gmp.tar.xz
	rm -rf "$DEPS/gmp-src"
	mkdir -p "$DEPS/gmp-src"
	tar -C "$DEPS/gmp-src" --strip-components=1 -xJf "$WORK/gmp.tar.xz"
	# generic C: no assembly for aarch64 Windows, and modp is rare enough
	(cd "$DEPS/gmp-src" &&
		./configure --prefix="$DEPS/gmp" --build="$(sh ./configfsf.guess)" \
			--host="$TRIPLE" --disable-shared --enable-static \
			--disable-assembly CC="$CC" CC_FOR_BUILD=cc CFLAGS="-O2" \
			>/dev/null &&
		make -j"$JOBS" >/dev/null && make install >/dev/null)
fi

# -- charon-svc ----------------------------------------------------------------

[ -f "$SRC/configure" ] || (cd "$SRC" && ./autogen.sh)

BUILD=$DEPS/strongswan
mkdir -p "$BUILD"
cd "$BUILD"
if [ ! -f Makefile ]; then
	"$SRC/configure" --host="$TRIPLE" --prefix=/ \
		--disable-defaults --enable-monolithic --enable-static \
		--disable-shared --enable-svc --enable-ikev2 --enable-vici \
		--enable-random --enable-nonce --enable-drbg \
		--enable-aes --enable-sha1 --enable-sha2 --enable-hmac --enable-gmp \
		--enable-curve25519 --enable-fips-prf --enable-kdf \
		--enable-x509 --enable-pem --enable-pubkey --enable-pkcs1 \
		--enable-constraints \
		--enable-socket-win --enable-kernel-iph \
		--enable-libipsec --enable-kernel-libipsec \
		--enable-eap-identity --enable-eap-aka --enable-eap-aka-http \
		--enable-p-cscf \
		CFLAGS="-O2 -mno-ms-bitfields" \
		CPPFLAGS="-I$DEPS/gmp/include" LDFLAGS="-L$DEPS/gmp/lib"
fi
# -all-static only at link time, configure's link tests can't use it
make -j"$JOBS" LDFLAGS="-L$DEPS/gmp/lib -all-static"

SVC=src/charon-svc/charon-svc.exe
if "$TRIPLE-objdump" -p "$SVC" | grep -iE 'DLL Name: (libstrongswan|libcharon|libgmp|libwinpthread|libc\+\+|libunwind)'; then
	echo "error: $SVC depends on non-system DLLs" >&2
	exit 1
fi

# -- package -------------------------------------------------------------------

fetch "https://www.wintun.net/builds/wintun-$WINTUN_VERSION.zip" \
	"$WINTUN_SHA256" wintun.zip

PKG=$DEPS/$NAME
rm -rf "$PKG" "$DEPS/wintun"
mkdir -p "$PKG/bin" "$PKG/lib/python" "$PKG/share/doc/strongswan-nekoims"
unzip -q "$WORK/wintun.zip" -d "$DEPS/wintun"
cp "$SVC" "$PKG/bin/charon-svc.exe"
"$TRIPLE-strip" "$PKG/bin/charon-svc.exe"
cp "$DEPS/wintun/wintun/bin/$WINTUN_ARCH/wintun.dll" "$PKG/bin/"
cp -R "$SRC/src/libcharon/plugins/vici/python/vici" "$PKG/lib/python/vici"
find "$PKG/lib/python" -name '__pycache__' -prune -exec rm -rf {} +
cp "$SRC/COPYING" "$SRC/LICENSE" "$PKG/share/doc/strongswan-nekoims/"
cp "$DEPS/wintun/wintun/LICENSE.txt" \
	"$PKG/share/doc/strongswan-nekoims/wintun-LICENSE.txt"
cat > "$PKG/share/doc/strongswan-nekoims/README" <<EOF
strongSwan $VERSION (NekoIMS fork), static monolithic charon-svc for
windows-$ARCH, with Wintun $WINTUN_VERSION.

  bin/charon-svc.exe   built-in plugins: $(sed -n 's/^charon_plugins = *//p' Makefile)
  bin/wintun.dll       loaded by kernel-libipsec for its TUN adapter
  lib/python/vici      strongSwan's vici Python client (pure Python)

charon-svc runs in the console when not started as a service and reads its
settings from %STRONGSWAN_CONF%. It needs Administrator rights for the
Wintun adapter. The NekoIMS dialer (dialers/strongswan-dialer.py) generates
that file and drives it over vici (TCP on localhost).
EOF

rm -f "$OUTDIR/$NAME.zip"
(cd "$DEPS" && zip -qr "$OUTDIR/$NAME.zip" "$NAME")
(cd "$OUTDIR" && sha256sum "$NAME.zip" > "$NAME.zip.sha256")
echo "built $OUTDIR/$NAME.zip"
