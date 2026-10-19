/*
 * @file    ngx_http_gk5z_module.c
 * @project GATEKEEPER WAF (GK5Z Engine)
 * @brief   High-performance TLS Session Fingerprinting and Anomaly Detection
 * @date    19.10.2026
 *
 * @copyright (c) 2026 GATEKEEPER Project
 * @license   GNU General Public License v3.0 (GPLv3)
 * @see       github.com/htmus/gk5z-openresty
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_log.h>
#include <ngx_md5.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <stdint.h>
#include <netinet/tcp.h>
#include <ngx_string.h>
#include "ngx_gatekeeper_struct.h"
#include "ngx_http_gk5z_module.h"
#include "ngx_http_redis_pool.h"
//#include <openssl/err.h>

extern ngx_module_t ngx_http_gkstat_module; // We declare that we will reference the gkstat module.
static ngx_http_variable_t gk5z_list_variables[] = {
    {ngx_string("http_gk5z_tls_supp_ver"), NULL, ngx_http_tls_supp_ver, 0, NGX_HTTP_VAR_NOCACHEABLE, 0},
    {ngx_string("http_gk5z_tls_supp_groups"), NULL, ngx_http_tls_supp_groups, 0, NGX_HTTP_VAR_NOCACHEABLE, 0},
    {ngx_string("ngx_gk5z_tls_psk_modes"), NULL, ngx_http_tls_psk_modes, 0, NGX_HTTP_VAR_NOCACHEABLE, 0},
    {ngx_string("http_gk5z_gk5z"), NULL, ngx_http_gk5z, 0, NGX_HTTP_VAR_NOCACHEABLE, 0},
    {ngx_string("http_gk5z_random"), NULL, ngx_http_gk_ssl_random_variable, 0, NGX_HTTP_VAR_NOCACHEABLE, 0},
    {ngx_string("http_gk5z_SNI"), NULL, ngx_http_gk5zSNI, 0, NGX_HTTP_VAR_NOCACHEABLE, 0},
    {ngx_string("http_gk5z_client_alpn"), NULL, ngx_http_gk5z_client_alpn_string, 0, NGX_HTTP_VAR_NOCACHEABLE, 0},
    {ngx_string("http_gk5z_client_extn"), NULL, ngx_http_gk5z_client_extn, 0, NGX_HTTP_VAR_NOCACHEABLE, 0},
    {ngx_string("http_gk5z_client_ciph"), NULL, ngx_http_gk5z_client_ciph, 0, NGX_HTTP_VAR_NOCACHEABLE, 0},
    {ngx_string("http_gk5z_client_algs"), NULL, ngx_http_tls_supp_algs, 0, NGX_HTTP_VAR_NOCACHEABLE, 0},
    {ngx_null_string, NULL, NULL, 0, 0, 0}
};
//-----------------------------------------------------
static ngx_int_t
ngx_http_gk5z_init(ngx_conf_t *cf) {
    size_t sz = 0;
    size_t vars_len = sizeof(gk5z_list_variables) / sizeof(gk5z_list_variables[0]);
    ngx_http_variable_t *var;

    for (sz = 0; sz < vars_len - 1; sz++) {
        var = ngx_http_add_variable(cf, &gk5z_list_variables[sz].name, gk5z_list_variables[sz].flags);
        if (var == NULL) {
            continue;
        }
        *var = gk5z_list_variables[sz];
    }
    return NGX_OK;
}
//-----------------------------------------------------
// Helper function for comparison
static int compare_uint16(const void *a, const void *b) {
    uint16_t ua = *(const uint16_t *)a;
    uint16_t ub = *(const uint16_t *)b;
    if (ua < ub) return -1;
    if (ua > ub) return 1;
    return 0;
}
//-----------------------------------------------------
static ngx_int_t
ngx_http_gk5zSNI(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data)
{
    u_char *buf;

    buf = ngx_pnalloc(r->pool, 1);
    if (buf == NULL) {
        v->not_found = 1;
        return NGX_ERROR;
    }

    const char *sni = NULL;

    if (r->connection->ssl) {
        sni = SSL_get_servername(
            r->connection->ssl->connection,
            TLSEXT_NAMETYPE_host_name
        );
    }

    if (sni) {
        in_addr_t addr = ngx_inet_addr((u_char *)sni, ngx_strlen(sni));

        if (addr != INADDR_NONE && addr != INADDR_ANY) {
            *buf = '3'; // IPv4
        }
        else if (ngx_strchr(sni, ':')) {
            *buf = '2'; // IPv6 (or garbage with ':')
        }
        else {
            *buf = '1'; // domain
        }
    }
    else {
        *buf = '0'; // SNI missing
    }

    v->len = 1;
    v->data = buf;
    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;

    return NGX_OK;
}
//-----------------------------------------------------
static int is_grease_value(uint16_t cipher) {
    for (size_t i = 0; i < sizeof(GREASE) / sizeof(GREASE[0]); i++) {
        if (cipher == GREASE[i]) {
            return 1;
        }
    }
    return 0;
}
//-----------------------------------------------------
static gk5z_processed_list_t
uint16ArrToString(ngx_connection_t *c, uint16_t *int_buf, size_t item_count, char ExGREASE) {
    gk5z_processed_list_t result = { NULL, 0 };

    if (int_buf != NULL && item_count > 0 && item_count < MAX_TLS_ITEMS_LIMIT) {

        uint16_t tmp_buf[MAX_TLS_ITEMS_LIMIT];

        // Copy the values, excluding GREASE if necessary.
        for (ngx_uint_t i = 0; i < item_count; i++) {
            if (!ExGREASE || !is_grease_value(int_buf[i])) {
                tmp_buf[result.count++] = int_buf[i];
            }
        }

        if(result.count) {
        // Sorting using qsort
            if (result.count > 1 && ExGREASE) {
                qsort(tmp_buf, result.count, sizeof(uint16_t), compare_uint16);
            }

            ngx_uint_t buf_len = result.count * 5 + 1;  // 4 hex digits + ',' for each except the last + '\0'
            u_char *str_buf = ngx_pnalloc(c->pool, buf_len);
            if (str_buf != NULL) {
                ngx_memzero(str_buf, buf_len);
                u_char *p = str_buf;

                for (ngx_uint_t i = 0; i < result.count; i++) {
                    snprintf((char *)p, 5, "%04x", tmp_buf[i]);
                    p += 4;
                    if (i < result.count - 1) *p++ = ',';
                }
                result.str = str_buf;
            } else ngx_log_error(NGX_LOG_ERR, c->log, 0, "ngx_http_gk5z_module: Memory allocation failed for str_buf(uint16ArrToStr)");
        }
    }
    return result;
}
//-----------------------------------------------------
static gk5z_processed_list_t
uint16ArrToString_src(ngx_connection_t *c, uint16_t *int_buf, size_t item_count) {
    gk5z_processed_list_t result = { NULL, 0 };

    if (int_buf != NULL && item_count > 0 && item_count < 100) {

        uint16_t tmp_buf[100];

        // Copy the values, excluding GREASE if necessary.
        for (ngx_uint_t i = 0; i < item_count; i++) {
            tmp_buf[result.count++] = int_buf[i];
        }

        if(result.count) {
            ngx_uint_t buf_len = result.count * 5 + 1;
            u_char *str_buf = ngx_pnalloc(c->pool, buf_len);
            if (str_buf != NULL) {
                ngx_memzero(str_buf, buf_len);
                u_char *p = str_buf;

                for (ngx_uint_t i = 0; i < result.count; i++) {
                    snprintf((char *)p, 5, "%04x", tmp_buf[i]);
                    p += 4;
                    if (i < result.count - 1) *p++ = ',';
                }
                result.str = str_buf;
            } else ngx_log_error(NGX_LOG_ERR, c->log, 0, "ngx_http_gk5z_module: Memory allocation failed for str_buf(uint16ArrToStr)");
        }
    }
    return result;
}
//-----------------------------------------------------

static u_char*
uint8ArrToString(ngx_connection_t *c, uint8_t *int_buf, size_t item_count) {
    if (int_buf == NULL || item_count == 0 || item_count > 256) {
        return NULL;
    }
    
    // Sorting for uint8_t is usually not needed, but it can be added if needed.
    size_t buf_len = item_count * 3; // 2 hex + 1 ','
    u_char *str_buf = ngx_pnalloc(c->pool, buf_len);
    if (str_buf == NULL) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0, "Failed to allocate memory for uint8 string");
        return NULL;
    }

    u_char *p = str_buf;
    for (size_t i = 0; i < item_count; i++) {
        p = ngx_sprintf(p, "%02x", int_buf[i]);
        if (i < item_count - 1) {
            *p++ = ',';
        }
    }
    
    return str_buf;
}
// --------------------------------------------------------
static ngx_int_t
ngx_http_gk_ssl_random_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {
    u_char *p;
    ngx_connection_t *c;
    unsigned char client_random[32];
    size_t len;

    c = r->connection;

    // 1. Checking for an SSL connection
    if (c->ssl == NULL || c->ssl->connection == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    // 2. Allocating memory in the query pool
    // We need exactly 64 bytes (32 bytes * 2 characters per byte).
    // The null terminator in Nginx variables is not required, v->len is important.
    p = ngx_pnalloc(r->pool, 64);
    if (p == NULL) {
        return NGX_ERROR;
    }

    // 3. Extracting raw data from OpenSSL
    // SSL_get_client_random returns the number of bytes copied
    len = SSL_get_client_random(c->ssl->connection, client_random, sizeof(client_random));

    if (len != 32) {
        // If suddenly OpenSSL did not return 32 bytes (impossible for correct TLS, but for security)
        v->not_found = 1;
        return NGX_OK;
    }

    // 4. Convert to HEX (Nginx Way)
    // This function will automatically convert 32 bytes into 64 characters [0-9a-f] (lowercase)
    ngx_hex_dump(p, client_random, 32);

    // 5. Filling the variable
    v->len = 64;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = p;

    return NGX_OK;
}
// --------------------------------------------------------
static ngx_int_t
ngx_http_tls_supp_algs(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {

    if(ngx_http_gk5z_checkParam(r) != NGX_OK) {
        v->not_found = 1;
        return NGX_ERROR;
    }

    ngx_connection_t *c = r->connection;

    if (c->ssl->sglgs != NULL && c->ssl->sglgs_sz > 0 && c->ssl->sglgs_sz < 100) {
        // Calling the function
        gk5z_processed_list_t processed_list = uint16ArrToString_src(c, c->ssl->sglgs, c->ssl->sglgs_sz); // 0 - do not clean from GREASE

        // We check the result
        if (processed_list.str != NULL && processed_list.count > 0) {
        // Setting the value of the nginx variable
            v->data = processed_list.str;
            v->len = ngx_strlen(processed_list.str); // We use ngx_strlen for reliability
            v->valid = 1;
            v->no_cacheable = 0; // This data is stable for the client and can be cached.
            v->not_found = 0;
        } else {
            // If the function returns NULL or an empty list, we consider the variable not found.
            v->not_found = 1;
        }
    }
    return NGX_OK;
}
//-----------------------------------------------------
static ngx_int_t
ngx_http_tls_supp_ver(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {

    if(ngx_http_gk5z_checkParam(r) != NGX_OK) {
        v->not_found = 1;
        return NGX_ERROR;
    }

    ngx_connection_t *c = r->connection;

    if (c->ssl->supp_vers != NULL && c->ssl->supp_vers_sz > 0 && c->ssl->supp_vers_sz < 100) {
        gk5z_processed_list_t processed_list = uint16ArrToString(c, c->ssl->supp_vers, c->ssl->supp_vers_sz, 1);

        // We check the result
        if (processed_list.str != NULL && processed_list.count > 0) {
        // Setting the value of the nginx variable
            v->data = processed_list.str;
            v->len = ngx_strlen(processed_list.str);
            v->valid = 1;
            v->no_cacheable = 1;
            v->not_found = 0;
        } else {
            // If the function returns NULL or an empty list, we consider the variable not found.
            v->not_found = 1;
        }
    }
    return NGX_OK;
}
//-----------------------------------------------------
static ngx_int_t
ngx_http_gk5z_client_ciph(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {

    if(ngx_http_gk5z_checkParam(r) != NGX_OK) {
        v->not_found = 1;
        return NGX_ERROR;
    }

    ngx_connection_t *c = r->connection;

    if (c->ssl->ciph != NULL && c->ssl->ciph_sz > 0 && c->ssl->ciph_sz < 100) {
        gk5z_processed_list_t processed_list = uint16ArrToString_src(c, c->ssl->ciph, c->ssl->ciph_sz);
        if (processed_list.str != NULL && processed_list.count > 0) {
            v->data = processed_list.str;
            v->len = ngx_strlen(processed_list.str);
            v->valid = 1;
            v->no_cacheable = 1;
            v->not_found = 0;
        } else {
            v->not_found = 1;
        }
    }
    return NGX_OK;
}
//-----------------------------------------------------
static ngx_int_t
ngx_http_gk5z_client_extn(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {

    if(ngx_http_gk5z_checkParam(r) != NGX_OK) {
        v->not_found = 1;
        return NGX_ERROR;
    }

    ngx_connection_t *c = r->connection;

    if (c->ssl->extn != NULL && c->ssl->extn_sz > 0 && c->ssl->extn_sz < 100) {
        gk5z_processed_list_t processed_list = uint16ArrToString_src(c, c->ssl->extn, c->ssl->extn_sz);
        if (processed_list.str != NULL && processed_list.count > 0) {
            v->data = processed_list.str;
            v->len = ngx_strlen(processed_list.str);
            v->valid = 1;
            v->no_cacheable = 1;
            v->not_found = 0;
        } else {
            v->not_found = 1;
        }
    }
    return NGX_OK;
}
//-----------------------------------------------------
static ngx_int_t
ngx_http_tls_supp_groups(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {

    if(ngx_http_gk5z_checkParam(r) != NGX_OK) {
        v->not_found = 1;
        return NGX_ERROR;
    }

    ngx_connection_t *c = r->connection;

    if (c->ssl->supp_groups != NULL && c->ssl->supp_groups_sz > 0 && c->ssl->supp_groups_sz < 100) {
        gk5z_processed_list_t processed_list = uint16ArrToString_src(c, c->ssl->supp_groups, c->ssl->supp_groups_sz);
        if (processed_list.str != NULL && processed_list.count > 0) {
            v->data = processed_list.str;
            v->len = ngx_strlen(processed_list.str);
            v->valid = 1;
            v->no_cacheable = 1;
            v->not_found = 0;
        } else {
            v->not_found = 1;
        }
    }
    return NGX_OK;
}
//-----------------------------------------------------
static ngx_int_t
ngx_http_tls_psk_modes(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {
    u_char *tsp_buf;
    u_char *p;              // Pointer to the current recording position

    if(ngx_http_gk5z_checkParam(r) != NGX_OK) {
        v->not_found = 1;
        return NGX_ERROR;
    }

    ngx_connection_t *c = r->connection;

    if (c->ssl->psk_modes != NULL && c->ssl->psk_modes_sz > 0 && c->ssl->psk_modes_sz < 100) {
        uint8_t *sver = c->ssl->psk_modes;
        ngx_uint_t clen = c->ssl->psk_modes_sz;
        ngx_uint_t buf_len = clen * 3 + 1;

        tsp_buf = ngx_pnalloc(r->pool, buf_len);
        if (tsp_buf == NULL) {
            ngx_log_error(NGX_LOG_ERR, c->log, 0, "ngx_http_gk5z_module: Memory allocation failed for tsp_buf(tls_psk_modes)");
            v->not_found = 1;
            return NGX_ERROR;
        }
// Forming a group string
        ngx_memzero(tsp_buf,buf_len);
        p = tsp_buf;

        for (ngx_uint_t i = 0; i < clen; i++) {
            snprintf((char *)p, 3, "%02x", sver[i]);
            p += 2;
            if(i < clen - 1) *p++ = ',';
        }

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "tsp_buf: \"%s\", clen=%ui", tsp_buf, clen);
    } else {
        tsp_buf = 0;
        p = 0;
    }

    size_t len = p - tsp_buf;  // length up to \0
    if (len == 0) {
        v->not_found = 1;
        return NGX_OK;
    }
    v->data = tsp_buf;
    v->len = len;
    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;

    return NGX_OK;
}
//-----------------------------------------------------
// Helper function for hashing
static void
ngx_http_gk5z_calculate_hash_str(u_char *dest_hex, const u_char *src_str)
{
    if (src_str != NULL && ngx_strlen(src_str) > 0) {
        unsigned char digest[SHA256_DIGEST_LENGTH];
        SHA256(src_str, ngx_strlen(src_str), digest);
        // WRITE EXACTLY 12 characters (6 bytes)
        snprintf((char*)dest_hex, 13, "%02x%02x%02x%02x%02x%02x",
                     digest[0], digest[1], digest[2], digest[3], digest[4], digest[5]);
    } else {
        ngx_memcpy(dest_hex, "000000000000", 12);
    }
    dest_hex[12] = '\0'; // We guarantee a null terminator
}
//-----------------------------------------------------
static ngx_int_t
ngx_http_gk5z(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data)
{
    u_char *buf, *p;
    ngx_connection_t *c = r->connection;
    size_t written = 0; // To store the result of snprintf

    if (c->ssl == NULL || c->ssl->connection == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    SSL *s = c->ssl->connection;
    SSL_SESSION *sess = SSL_get0_session(s);

    buf = ngx_pnalloc(r->pool, GK5Z_MAX_RAW_SIZE);   //GK5Z_MAX_RAW_SIZE = 256
    if (buf == NULL) {
        v->not_found = 1;
        return NGX_ERROR;
    }
    p = buf;

    //We immediately receive all the data for the hashes
    gk5z_processed_list_t versions = uint16ArrToString(c, c->ssl->supp_vers, c->ssl->supp_vers_sz, 1);
    gk5z_processed_list_t ciphers = uint16ArrToString(c, c->ssl->ciph, c->ssl->ciph_sz, 1);
    gk5z_processed_list_t exts = uint16ArrToString(c, c->ssl->extn, c->ssl->extn_sz, 1);
    gk5z_processed_list_t groups = uint16ArrToString(c, c->ssl->supp_groups, c->ssl->supp_groups_sz, 1);
    gk5z_processed_list_t algs = uint16ArrToString(c, c->ssl->sglgs, c->ssl->sglgs_sz, 1);

    // --- Block 1: "Statics" and session flags ---
    written = snprintf((char *)p, 512 - (p - buf), "%c%02zu%02zu%02zu%02zu%02zu%02zu%04zu%02zu%04x",
        SSL_session_reused(s) ? 't' : 'f',
        versions.count,
        c->ssl->compr_mt_sz,
        groups.count,
        ciphers.count,
        exts.count,
        algs.count,
        c->ssl->padding_len,
        c->ssl->psk_modes_sz,
        (unsigned int)c->ssl->record_size_limit);
    p += written;
        
    // --- Block 2: Session/Ticket Flags ---
    unsigned int sess_id_len = 0;
    const unsigned char *sess_id = sess ? SSL_SESSION_get_id(sess, &sess_id_len) : NULL;
    *p++ = (sess_id && sess_id_len > 0) ? 't' : 'f';
    *p++ = 'f'; // Ticket flag plug
    *p++ = '_';

    // --- Block 3: Session ID ---
    if (sess_id && sess_id_len >= 6) {
        p = ngx_hex_dump(p, (u_char *)sess_id, 6);
    } else {
        p = ngx_cpymem(p, "000000000000", 12);
    }
    *p++ = '_';

    // --- Block 4: Ticket ID ---
    p = ngx_cpymem(p, "000000000000", 12); // Ticket ID Plug
    *p++ = '_';

    // --- Block 5: Handshake time and Client Random ---
    written = snprintf((char *)p, 512 - (p - buf), "%lu_", (unsigned long)c->ssl->handshake_time_us);
    p += written;
    
    unsigned char client_random[32];
    if (SSL_get_client_random(s, client_random, sizeof(client_random)) == sizeof(client_random)) {
        written = snprintf((char *)p, 512 - (p - buf), "%02x%02x%02x%02x",
                           client_random[0], client_random[1], client_random[2], client_random[3]);
        p += written;
    } else {
        p = ngx_cpymem(p, "00000000", 8);
    }
    *p++ = '_';
    
    // --- Block 6: Hashes ---
    u_char hash_buf[13];

    // 6.1. The first compression method
    if (c->ssl->compr_mt_sz > 0) {
        written = snprintf((char *)p, 512 - (p - buf), "%02x_", c->ssl->compr_mt[0]);
        p += written;
    } else {
        p = ngx_cpymem(p, "00_", 3);
    }
    
    // 6.2. Hash Supported Versions
    ngx_http_gk5z_calculate_hash_str(hash_buf, versions.str);
    p = ngx_cpymem(p, hash_buf, 12);
    *p++ = '_';
    
    // 6.3. Hash Ciphers
    ngx_http_gk5z_calculate_hash_str(hash_buf, ciphers.str);
    p = ngx_cpymem(p, hash_buf, 12);
    *p++ = '_';
    
    // 6.4. Hash Extensions
    ngx_http_gk5z_calculate_hash_str(hash_buf, exts.str);
    p = ngx_cpymem(p, hash_buf, 12);
    *p++ = '_';

    // 6.5. Hash Supported Groups
    ngx_http_gk5z_calculate_hash_str(hash_buf, groups.str);
    p = ngx_cpymem(p, hash_buf, 12);
    *p++ = '_';
    
    // 6.6. Hash Signature Algorithms
    ngx_http_gk5z_calculate_hash_str(hash_buf, algs.str);
    p = ngx_cpymem(p, hash_buf, 12);
    *p++ = '_';

    // 6.7. Hash PSK modes
    u_char *str_psk_modes = uint8ArrToString(c, c->ssl->psk_modes, c->ssl->psk_modes_sz);
    ngx_http_gk5z_calculate_hash_str(hash_buf, str_psk_modes);
    p = ngx_cpymem(p, hash_buf, 12);

    // --- FINAL ---
    v->len = p - buf;
    v->data = buf;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
}
//-----------------------------------------------------
//ALPN
static ngx_int_t
ngx_http_gk5z_client_alpn_string(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {
    if(ngx_http_gk5z_checkParam(r) != NGX_OK) {
        v->not_found = 1;
        return NGX_ERROR;
    }

    SSL *ssl = r->connection->ssl->connection;
    if (ssl == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "gk5z_CALPN: Unable to get SSL connection");
        return NGX_OK;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, r->connection->log, 0, "Entering ssl_gk5z_client_alpn_string, SSL ptr: %p", ssl);

    // Checking first_alpn (filled in ngx_SSL_early_cb_fn)
    if (r->connection->ssl->client_alpns) {
        size_t len = ngx_strlen(r->connection->ssl->client_alpns);
        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, r->connection->log, 0, "First ALPN found: %s", r->connection->ssl->client_alpns);

        v->data = ngx_palloc(r->pool, len + 1);
        if (v->data == NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Memory allocation failed for client ALPN string");
            return NGX_ERROR;
        }
        ngx_memcpy(v->data, r->connection->ssl->client_alpns, len);
        v->data[len] = '\0';
        v->len = len;
        v->valid = 1;
        v->no_cacheable = 1;
        v->not_found = 0;
        return NGX_OK;
    } else {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "No first ALPN found in ssl->first_alpn");
    }

    // Return "none" as a fallback
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "No ALPN found, using 'none'");
    ngx_str_t none_str = ngx_string("none");
    v->data = (u_char *)ngx_pstrdup(r->pool, &none_str);
    if (v->data == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Memory allocation failed for 'none' string");
        return NGX_ERROR;
    }
    v->len = none_str.len;
    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;
    return NGX_OK;
}
//-----------------------------------------------------
static ngx_int_t
ngx_http_gk5z_checkParam(ngx_http_request_t *r) {
    if (r->connection == NULL)
    {
        return NGX_ERROR;
    }
    ngx_connection_t *c = r->connection;
    if (c->ssl == NULL) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0, "gk5z: SSL is NULL");
        return NGX_ERROR;
    }
    if (c->ssl->connection == NULL) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0, "gk5z: SSL connection is NULL");
        return NGX_ERROR;
    }
    return NGX_OK;
}
//-----------------------------------------------------
static ngx_command_t  ngx_http_gk5z_commands[] = {
    ngx_null_command
};
//-----------------------------------------------------
static ngx_http_module_t ngx_http_gk5z_module_ctx = {
    NULL,                  /* preconfiguration */
    ngx_http_gk5z_init,    /* postconfiguration */
    NULL,                  /* create main configuration */
    NULL,                  /* init main configuration */
    NULL,                  /* create server configuration */
    NULL,                  /* merge server configuration */
    NULL,                  /* create location configuration */
    NULL                   /* merge location configuration */
};
ngx_module_t ngx_http_gk5z_module = {
    NGX_MODULE_V1,
    &ngx_http_gk5z_module_ctx,    /* module context */
    ngx_http_gk5z_commands,       /* module directives */
    NGX_HTTP_MODULE,              /* module type */
    NULL,                         /* init master */
    NULL,                         /* init module */
    NULL,                         /* init process */
    NULL,                         /* init thread */
    NULL,                         /* exit thread */
    NULL,                         /* exit process */
    NULL,                         /* exit master */
    NGX_MODULE_V1_PADDING
};