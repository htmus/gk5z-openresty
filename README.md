# GK5Z Engine: Advanced TLS Session Fingerprinting & Compliance Verification

The **GK5Z Engine** is a high-performance, infrastructure-level security framework designed for **OpenResty** and **OpenSSL**. It provides low-overhead, deep TLS traffic inspection, high-precision session profiling, and real-time anomaly tracking directly within the web server's core layer.

Unlike standard TLS fingerprinting implementations (such as basic JA3 or official JA4), the GK5Z Engine is explicitly architected to maintain complete compatibility with the native OpenResty Lua lifecycle. It introduces non-destructive hooks that guarantee **all stages of `client_hello_by_lua*` execution are fully preserved and functional**.

---

## GK5Z Fingerprint Format Specification

A standard GK5Z string is divided into 12 distinct blocks separated by underscores (`_`):
`GK5Z: f0201041517080000010000tf_8355b0503b23_000000000000_84_e4892fe1_00_951149100763_8daaf6152771_ecb626e094b7_646c356617d7_0e284abb3885_000000000000`

For the full architectural format specification, byte-string breakdowns, and internal mechanics, please refer to the version-specific documentation below.

---

## Supported Releases & Deployment Guides

This repository is organized by target OpenResty release branches. Navigate to the specific directory below to find compatible core C-patches, extension modules, automated build tools, and production-ready configuration stubs:

* [📂 OpenResty 1.27.1.2 + OpenSSL 3.4.1](./1.27.1.2/) — **Stable LTS Branch (GK5Z v1.0)**
* 📂 OpenResty 1.31.1.1 + OpenSSL 3.5.6 — *Coming Soon (Production Testing Stage)*

---

## License

This project is licensed under the **GNU General Public License v3.0 (GPLv3)** - see the [LICENSE](LICENSE) file for details.
