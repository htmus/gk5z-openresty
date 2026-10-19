/*
 * @file    ngx_http_gk5z_module.h
 * @project GATEKEEPER WAF (GK5Z Engine)
 * @brief   High-performance TLS Session Fingerprinting and Anomaly Detection
 * @date    19.10.2026
 *
 * @copyright (c) 2026 GATEKEEPER Project
 * @license   GNU General Public License v3.0 (GPLv3)
 * @see       github.com/htmus/gk5z-openresty
 */

#include <ngx_http.h>
#include <ngx_core.h>
#include <stdint.h>

 #define MAX_TLS_ITEMS_LIMIT 256

//Buffer limit for collecting z
#define GK5Z_MAX_RAW_SIZE 256

#ifndef OSSL_QUIC1_VERSION
#define OSSL_QUIC1_VERSION       0x0000001
#endif //OSSL_QUIC1_VERSION
//#define QUICV1_VERSION_INT  0x0001

//Structures
static const ngx_uint_t sslVerList_n[] = {
    SSL3_VERSION,
    TLS1_VERSION,
    TLS1_1_VERSION,
    TLS1_2_VERSION,
    TLS1_3_VERSION,
    DTLS1_VERSION,
    DTLS1_2_VERSION,
    DTLS1_BAD_VER,
    OSSL_QUIC1_VERSION,
};

static const uint16_t GREASE[] = {
    0x0a0a,
    0x1a1a,
    0x2a2a,
    0x3a3a,
    0x4a4a,
    0x5a5a,
    0x6a6a,
    0x7a7a,
    0x8a8a,
    0x9a9a,
    0xaaaa,
    0xbaba,
    0xcaca,
    0xdada,
    0xeaea,
    0xfafa,
};
static const uint16_t EXT_IGNORES[] = {
    0x0000, // server_name
//    0x000b, // ec_point_formats
//    0x0005, // status_request
//    0xff01, // renegotiation_info
    0x0010, // application_layer_protocol_negotiation
    0x0029, // pre_shared_key
    0x002a, // early_data
// --- The Main Enemies of Stability (Session Resumption & Noise) ---
    0x0015, // padding - CRITICAL! Chrome adds random padding, changing the length and hash.
    0x0023, // session_ticket - (TLS 1.2) Changed when the session is resumed.
    0xff01, // renegotiation_info - Varies depending on the state.
};

typedef struct {
    u_char *str;       // Pointer to the formatted string
    size_t count;      // Number of elements AFTER filtering
} gk5z_processed_list_t;


//Function declaration
//Initialize
static ngx_int_t ngx_http_gk5z_init(ngx_conf_t *cf);
//Helpers
static ngx_int_t ngx_http_gk5z_checkParam(ngx_http_request_t *r);
static u_char* uint8ArrToString(ngx_connection_t *c, uint8_t *int_buf, size_t item_count);

//gk5z
static ngx_int_t ngx_http_gk5z(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
//Auxiliary function
static void ngx_http_gk5z_calculate_hash_str(u_char *dest_hex, const u_char *src_str);

//Client ALPN
static ngx_int_t ngx_http_gk5z_client_alpn_string(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);

//gk5z
static int is_grease_value(uint16_t cipher);
static int compare_uint16(const void *a, const void *b);

//TLS supported versions
static ngx_int_t ngx_http_tls_supp_ver(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);

//TLS supported groups
static ngx_int_t ngx_http_tls_supp_groups(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);

//TLS PSK modes
static ngx_int_t ngx_http_tls_psk_modes(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);

//Client extensions
static ngx_int_t ngx_http_gk5z_client_extn(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);

//Client chiphers
static ngx_int_t ngx_http_gk5z_client_ciph(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);

//helpers
static gk5z_processed_list_t uint16ArrToString(ngx_connection_t *c, uint16_t *int_buf, size_t item_count, char ExGREASE);
static gk5z_processed_list_t uint16ArrToString_src(ngx_connection_t *c, uint16_t *int_buf, size_t item_count);

//Supported algorithms
static ngx_int_t ngx_http_tls_supp_algs(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);

static ngx_int_t ngx_http_gk_ssl_random_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);

static ngx_int_t ngx_http_gk5zSNI(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
