# OpenResty 1.27.1.2 + OpenSSL 3.4.1 GK5Z Data Extractor Patches

This repository contains infrastructure patches to extract raw TLS ClientHello metrics (GK5Z standard compliant) without breaking native OpenResty Lua ClientHello callbacks (`client_hello_by_lua*`). 

All complex scoring, thresholds, and banning logic should be implemented on the Lua layer using the exported variables.

---

## Key Features

* **Non-Destructive Call Chain:** Implements custom OpenSSL APIs to read ClientHello data without overtaking or breaking native Lua hooks.
* **Deep Cryptographic Profiling:** Extracts full handshake attributes including Cipher Suites, Extensions, ALPN, Compression, Supported Versions, Supported Groups, Signature Algorithms, Padding, PSK Modes, and RFC 8449 Record Size Limit.
* **High-Precision Timing:** Calculates exact TLS handshake durations (`handshake_time_us`) using native microsecond-level hardware clocks.
* **Nginx Native Variables:** Automatically populates compiled data into standard Nginx variables for immediate use inside Lua or access logs.
* **Asynchronous Metrics Export:** Implements a high-performance C-to-Redis pipeline to stream real-time atomic connection statistics and anomalies out of Shared Memory (SHM) to external storage/dashboards.

---

## Directory Structure

This repository is organized by OpenResty release versions. Navigate to the specific directory to find compatible patches, modules, and configuration examples.

```text
.
1.27.1.2/                      # Target directory for OpenResty 1.27.1.2 + OpenSSL 3.4.1
├── patches/                   # Core C-patches for OpenSSL and Nginx core
│   ├── openssl_3.4.1.patch
│   └── openresty_1.27.1.2.nginx.patch
├── modules/                   # Reference C-modules for metrics & export
│   ├── ngx_http_gk5z_module.c     - Fingerprint calculation engine
│   ├── ngx_http_gkstat_module.c   - In-memory metrics & SHM aggregation
│   └── ngx_http_redis_pool.c      - Lock-free reference Redis connection pool
├── config-examples/           # Production-ready configuration deployment stubs
│   ├── nginx.conf
│   └── gtk.conf
├── utils/                     # helper utilites
│   └── openresty.build.sh     # automatic build script for openresty.
└── readme.md                  # Version-specific installation guide
```

---

## Understanding TLS Fingerprinting & The GK5Z Standard

### What is TLS Fingerprinting?
When a client establishes an HTTPS connection, it sends a `ClientHello` message containing its supported cipher suites, extensions, versions, and cryptographic parameters. Because different operating systems, browsers, and automated tools (bots, scrapers, malware) use different TLS libraries and configurations, their `ClientHello` structures are unique. 

Traditional fingerprinting (like JA3 or standard JA4) creates a static hash of these parameters. However, modern advanced bots have learned **TLS Mimicry (Spoofing)**—they copy the exact list of ciphers and extensions of legitimate browsers (like Chrome or Firefox) to bypass passive security filters.

### Why GK5Z?
The **GK5Z** format goes beyond static hashing. It isolates the unique fingerprint of the client by combining the structural properties of the handshake with **runtime session metrics, cryptographic randomness, and hardware timing**. 

By evaluating properties like exact padding lengths, PSK modes, RFC 8449 Record Size Limits, and the precise execution speed of the cryptographic handshake (`handshake_time_us`), **GK5Z** makes it virtually impossible for automated tools to successfully impersonate human-driven web browsers, even if they completely spoof the static cipher lists.

---

## GK5Z Fingerprint Format Specification

A standard GK5Z string looks like this:
`GK5Z: f0201041517080000010000tf_8355b0503b23_000000000000_84_e4892fe1_00_951149100763_8daaf6152771_ecb626e094b7_646c356617d7_0e284abb3885_000000000000`

The string is divided into 12 distinct blocks separated by underscores (`_`).

| Block | Value (Example) | Type / Size | Description |
| :--- | :--- | :--- | :--- |
| **Block 1** | `f0201041517080000010000tf` | Mixed (25b) | **Session Metrics Byte-String** (See detailed breakdown below) |
| **Block 2** | `8355b0503b23` | Hex (12c) | First 12 characters of `session_id` (padded with `0` if empty) |
| **Block 3** | `000000000000` | Hex (12c) | First 12 characters of `ticket_id` (padded with `0` if empty) |
| **Block 4** | `84` | Dec (Var) | TLS handshake execution duration in microseconds (`handshake_time_us`) |
| **Block 5** | `e4892fe1` | Hex (8c) | First 4 bytes of Client Hello `Random` payload |
| **Block 6** | `00` | Hex (2c) | Code of the first client compression method (`00` if absent) |
| **Block 7** | `951149100763` | Hex (12c) | First 6 bytes of SHA256 hash from sorted **Supported Versions** (excluding GREASE) |
| **Block 8** | `8daaf6152771` | Hex (12c) | First 6 bytes of SHA256 hash from sorted **Ciphers List** (excluding GREASE) |
| **Block 9** | `ecb626e094b7` | Hex (12c) | First 6 bytes of SHA256 hash from sorted **Extensions List** (excluding GREASE) |
| **Block 10**| `646c356617d7` | Hex (12c) | First 6 bytes of SHA256 hash from sorted **Supported Groups** (excluding GREASE) |
| **Block 11**| `0e284abb3885` | Hex (12c) | First 6 bytes of SHA256 hash from sorted **Signature Algorithms** (excluding GREASE) |
| **Block 12**| `000000000000` | Hex (12c) | First 6 bytes of SHA256 hash from **PSK Modes** (currently reserved stub) |

### Block 1 Detailed Breakdown

Block 1 aggregates structural lengths and boolean state flags into a dense 25-character signature:

| Offset | Characters | Format | Description |
| :--- | :--- | :--- | :--- |
| `0` | 1 | Bool (`t`/`f`) | **SSL session reuse** status (`t` = true, `f` = false) |
| `1` | 2 | Dec | Count of client **Supported Versions** |
| `3` | 2 | Dec | Count of client **Compression Methods** (`01` usually means none) |
| `5` | 2 | Dec | Count of client **Supported Groups** |
| `7` | 2 | Dec | Count of client **Cipher Suites** |
| `9` | 2 | Dec | Count of client **TLS Extensions** |
| `11` | 2 | Dec | Count of client **Signature Algorithms** |
| `13` | 4 | Dec | **TLS Padding extension** exact length in bytes |
| `17` | 2 | Dec | Count of **PSK Kex Modes** |
| `19` | 4 | Hex | **RFC 8449 Record Size Limit** value (`0000` if absent) |
| `23` | 1 | Bool (`t`/`f`) | Active TLS context uses a **Session ID** (`t` = true, `f` = false) |
| `24` | 1 | Bool (`t`/`f`) | Active TLS context uses a **Session Ticket** (`t` = true, `f` = false) |


## Installation & Compilation Guide

### 1. Prerequisites (System Packages)

Before compiling the GK5Z Engine, install the required build tools and core dependencies on your system (Ubuntu/Debian based):

```bash
sudo apt update
sudo apt install build-essential perl make curl zlib1g-dev libssl-dev libpcre2-dev -y
sudo apt install libmaxminddb0 libmaxminddb-dev -y
```

### 2. Compilation Environment & Source Tree

To ensure the automated compilation script works without modifying internal paths, you must organize your workspace source tree inside a single root directory (e.g., `/root/or/`) exactly as follows:

```text
/<bulder_dir>/
├── nginx_gatekeeper_modules/     # Repository: 1.27.1.2/modules/
├── openresty-1.27.1.2/           # Vanilla OpenResty 1.27.1.2 source
├── openssl-3.4.1/                # Vanilla OpenSSL 3.4.1 source
├── pcre2-10.46/                  # Vanilla PCRE2 10.46 source
├── hiredis/                      # Official Hiredis source branch
├── libmaxminddb/                 # Official LibMaxMindDB source branch
├── openresty_1.27.1.2.nginx.patch
├── openssl_3.4.1.patch
└── build.sh                      # Automated build OpenResty helper script
```

### 3. Applying Core Infrastructure Patches

Navigate to your workspace root directory and execute the following commands to apply the GK5Z hooks directly into the OpenSSL and Nginx core layer:

```bash
# Patch OpenSSL state machine and structures
patch -p1 -d openssl-3.4.1 < openssl_3.4.1.patch

# Patch OpenResty (Nginx core & ngx_lua API)
patch -p1 -d openresty-1.27.1.2 < openresty_1.27.1.2.nginx.patch
```

### 4. Compiling Base Dependencies (Hiredis & OpenSSL)

Compile and prepare static assets for the external metrics pipeline:

```bash
# Build and install Hiredis shared assets
cd hiredis
make clean && make
sudo make install
cd ..

# Build custom standalone OpenSSL build env
cd openssl-3.4.1
if [ -f "Makefile" ]; then make clean; fi
./config --prefix=/opt/openssl-3.4.1-no-shared
make -j$(nproc)
sudo make install_sw
cd ..
```

---

## The Automated Build Script (`build.sh`)

Place the following automated orchestration script inside `/root/or/openresty-1.27.1.2/build.sh`. It handles the automated static compilation of `libmaxminddb` and links all security extensions into a unified OpenResty binary.

```bash
#!/bin/bash

# Abort script execution on any internal failure
set -e

# --- CONTEXT PATH DEFINITIONS ---
ROOT_DIR="write_you_full_dir"
MAXMIND_DIR="\$ROOT_DIR/libmaxminddb"
HIREDIS_DIR="\$ROOT_DIR/hiredis"
NGX_MODULES_DIR="\$ROOT_DIR/nginx_gatekeeper_modules"
OPENSSL_DIR="\$ROOT_DIR/openssl-3.4.1"
PCRE_DIR="\$ROOT_DIR/pcre2-10.46"

echo "======================================================="
echo "1. BUILDING STATIC DEPENDENCY: LibMaxMindDB"
echo "======================================================="
cd "\$MAXMIND_DIR"

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
cd src && make -j\$(nproc)
cd ..

if [ ! -f "src/.libs/libmaxminddb.a" ]; then
    echo "CRITICAL ERROR: libmaxminddb.a compile failure! Aborting."
    exit 1
fi
echo "MaxMindDB static layer built successfully."

echo "======================================================="
echo "2. CONFIGURING & COMPILING OPENRESTY WITH GK5Z ENGINE"
echo "======================================================="
cd "\$ROOT_DIR/openresty-1.27.1.2"

# Safe cleanup hook
if [ -f "Makefile" ]; then
    make clean
fi

./configure \
    --with-openssl=\$OPENSSL_DIR \
    --add-module=\$NGX_MODULES_DIR \
    --with-http_ssl_module \
    --with-stream \
    --with-stream_ssl_module \
    --with-stream_ssl_preread_module \
    --with-http_stub_status_module \
    --with-pcre=\$PCRE_DIR \
    --with-pcre-jit \
    --with-luajit \
    --with-http_v2_module \
    --with-cc-opt="-I\(HIREDIS_DIR -I\)MAXMIND_DIR/include" \
    --with-ld-opt="-L\$HIREDIS_DIR \
                   -lhiredis \
                   -Wl,--whole-archive \$MAXMIND_DIR/src/.libs/libmaxminddb.a -Wl,--no-whole-archive \
                   -Wl,-rpath,\$HIREDIS_DIR \
                   -Wl,-E" \
    --with-luajit-xcflags="-DLUAJIT_ENABLE_LUA52COMPAT" \
    -j\$(nproc)

echo "======================================================="
echo "Configuration complete. Executing OpenResty make..."
echo "======================================================="
make -j\$(nproc)

echo "======================================================="
echo "SUCCESS! Run 'sudo make install' to finalize deployment."
echo "======================================================="

make install

```

## Configuration & Integration

### 1. Redis Pool Configuration (`gtk.conf`)

The custom metrics engine utilizes a dedicated connection pool. Create a configuration file named `gtk.conf` to store your cluster connection settings:

```ini
[redis]
REDIS_HOST=127.0.0.1
REDIS_PORT=6379
REDIS_PASSWD=
REDIS_DBINDEX=1
REDIS_CONNECT_TIMEOUT=1000
REDIS_SEND_TIMEOUT=5000
REDIS_READ_TIMEOUT=5000
REDIS_KEEPALIVE_TIMEOUT=60000
REDIS_KEEPALIVE_POOLSIZE=10
REDIS_POOLSIZE=100
REDIS_WORK_POOLSIZE=100
STATS_RECORDS_TTL=600
```

> ⚠️ **CRITICAL DEVELOPER NOTE:** 
> Before compiling the modules, verify the absolute path to your `gtk.conf` file inside the reference implementation source file **`ngx_http_redis_pool.c`** (or change it to match your system deployment layout before execution).

---

### 2. Nginx Deployment Configuration (`nginx.conf`)

To activate the shared memory zones, global tracking counters, and verify the runtime output of the **GK5Z Engine**, adapt your `nginx.conf` as shown below. 

The framework populates native Nginx variables which can be read directly within your `content_by_lua_block` hooks.

```nginx.conf

worker_processes 5;
error_log  logs/error.log;
error_log  logs/debug.log  debug; # Enable for verbose infrastructure tracing

events {
    worker_connections  1024;
}

http {
    include       mime.types;
    default_type  "text/html";

    # --- Shared Memory Definitions for GK5Z Analytics ---
    lua_shared_dict settings 10m;         # Global system configuration cache
    lua_shared_dict anomaly_counters 10m; # Atomic SSL/TLS handshake anomaly counters
    gatekeeper_stats_shm gatekeeper 1m;   # Core C-module Shared Memory block

    lua_socket_log_errors off;
    lua_code_cache on;

    # --- HTTP Optimization & Slowloris Mitigation Stubs ---
    client_body_timeout 3s;
    client_header_timeout 3s;
    send_timeout 5s;
    client_header_buffer_size    1k;
    large_client_header_buffers  4 4k;
    client_body_buffer_size      10M;
    client_max_body_size         20M;

    server {
        listen      80;
        server_name default_server;
        return 301 https://hostrequest_uri;
    }

    server {
        listen 443 ssl;
        server_name superpc.ru;
        http2 on; # Native HTTP/2 activation style for verified branches
        
        root /usr/local/openresty/nginx/html;
        index index.php index.html;

        ssl_certificate /etc/ssl/certs/nginx-selfsigned.crt;
        ssl_certificate_key /etc/ssl/private/nginx-selfsigned.key;
        ssl_dhparam /etc/ssl/nginx_dhparam.pem;

        resolver 8.8.8.8 1.1.1.1 valid=300s ipv6=off;
        resolver_timeout 5s;

        # Lifecycle hooks stubbed for Lua security filters
        ssl_client_hello_by_lua_block { }
        header_filter_by_lua_block { }
        body_filter_by_lua_block { }

        location / {
            try_files \$uri uri/ /index.php?args;
        }

        # --- GK5Z Runtime Verification Endpoint ---
        location /check {
            default_type text/plain;
            content_by_lua_block {
                ngx.header["Content-Type"] = "text/html; charset=utf-8"
                local body = {
                    "GK5Z: ", ngx.var.http_gk5z_gk5z or "N/A", "<br>",
                    "Client extensions: ", ngx.var.http_gk5z_client_extn or "N/A", "<br>",
                    "Client ciphers: ", ngx.var.http_gk5z_client_ciph or "N/A", "<br>",
                    "Client supp.versions: ", ngx.var.http_gk5z_tls_supp_ver or "N/A", "<br>",
                    "Client supp.groups: ", ngx.var.http_gk5z_tls_supp_groups or "N/A", "<br>",
                    "Client supp.algorithms: ", ngx.var.http_gk5z_client_algs or "N/A", "<br>",
                    "Client ALPN: ", ngx.var.http_gk5z_client_alpn or "N/A", "<br>",
                    "Client random:", ngx.var.http_gk5z_random or "N/A", "<br>",
                    "PSK modes: ", ngx.var.ngx_gk5z_tls_psk_modes or "N/A", "<br>",
                    "SNI: ", ngx.var.http_gk5z_SNI or "N/A", "<br>",
                    "==============================================<br>",
                }
                ngx.say(table.concat(body))
                return ngx.exit(ngx.OK)
            }
        }

        set \$gk_api_data "";
        location ~ \.php\$ {
            include fastcgi_params;
            fastcgi_pass unix:/run/php/php7.4-fpm.sock;
            fastcgi_index index.php;
            fastcgi_param SCRIPT_FILENAME \$request_filename;
            fastcgi_param GK_API_DATA \$gk_api_data;
        }
    }
}
```

