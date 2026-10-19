#!/bin/bash

# Abort script execution on any internal failure
set -e

# --- CONTEXT PATH DEFINITIONS ---
ROOT_DIR="/root/or"
MAXMIND_DIR="$ROOT_DIR/libmaxminddb"
HIREDIS_DIR="$ROOT_DIR/hiredis"
NGX_MODULES_DIR="$ROOT_DIR/nginx_gatekeeper_modules"
OPENSSL_DIR="$ROOT_DIR/openssl-3.4.1"
PCRE_DIR="$ROOT_DIR/pcre2-10.46"

echo "======================================================="
echo "1. BUILDING STATIC DEPENDENCY: LibMaxMindDB"
echo "======================================================="
cd "$MAXMIND_DIR"

if [ ! -f "./configure" ]; then
    echo "Bootstrapping Autotools context..."
    ./bootstrap
fi

echo "Configuring MaxMindDB static target..."
./configure --enable-static --disable-shared

if [ -f "Makefile" ]; then
    make clean || true
fi

echo "Compiling MaxMindDB core assets..."
cd src && make -j$(nproc)
cd ..

if [ ! -f "src/.libs/libmaxminddb.a" ]; then
    echo "CRITICAL ERROR: libmaxminddb.a compile failure! Aborting."
    exit 1
fi
echo "MaxMindDB static layer built successfully."

echo "======================================================="
echo "2. CONFIGURING & COMPILING OPENRESTY WITH GK5Z ENGINE"
echo "======================================================="
cd "$ROOT_DIR/openresty-1.27.1.2"

# Safe cleanup hook
if [ -f "Makefile" ]; then
    make clean
fi

./configure \
    --with-openssl=$OPENSSL_DIR \
    --add-module=$NGX_MODULES_DIR \
    --with-http_ssl_module \
    --with-stream \
    --with-stream_ssl_module \
    --with-stream_ssl_preread_module \
    --with-http_stub_status_module \
    --with-pcre=$PCRE_DIR \
    --with-pcre-jit \
    --with-luajit \
    --with-http_v2_module \
    \
    --with-cc-opt="-I$HIREDIS_DIR -I$MAXMIND_DIR/include" \
    \
    --with-ld-opt="-L$HIREDIS_DIR \
                   -lhiredis \
                   -Wl,--whole-archive $MAXMIND_DIR/src/.libs/libmaxminddb.a -Wl,--no-whole-archive
                   -Wl,-rpath,$HIREDIS_DIR \
                   -Wl,-E" \
    \
    --with-luajit-xcflags="-DLUAJIT_ENABLE_LUA52COMPAT" \
    -j$(nproc)

echo "======================================================="
echo "Configuration complete. Executing OpenResty make..."
echo "======================================================="
make -j$(nproc)

echo "======================================================="
echo "SUCCESS! Run 'sudo make install' to finalize deployment."
echo "======================================================="
