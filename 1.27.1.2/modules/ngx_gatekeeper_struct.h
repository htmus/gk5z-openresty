/*
 * @file    ngx_gatekeeper_struct.h
 * @project GATEKEEPER WAF (GK5Z Engine)
 * @brief   High-performance TLS Session Fingerprinting and Anomaly Detection
 * @date    19.10.2026
 *
 * @copyright (c) 2026 GATEKEEPER Project
 * @license   GNU General Public License v3.0 (GPLv3)
 * @see       github.com/htmus/gk5z-openresty
 */

#ifndef NGX_HTTP_GK5Z_MODULE_STRUCT_H
#define NGX_HTTP_GK5Z_MODULE_STRUCT_H

//#include <ngx_http.h>
#include <ngx_core.h>
#include <stdint.h>
#include "hiredis/hiredis.h"

typedef struct {
    ngx_str_t  host;                 // REDIS_HOST
    ngx_uint_t port;                 // REDIS_PORT
    ngx_str_t  passwd;               // REDIS_PASSWD
    ngx_uint_t dbindex;              // REDIS_DBINDEX
    ngx_uint_t connect_timeout;      // REDIS_CONNECT_TIMEOUT (мс)
    ngx_uint_t send_timeout;         // REDIS_SEND_TIMEOUT (мс)
    ngx_uint_t read_timeout;         // REDIS_READ_TIMEOUT (мс)
    ngx_uint_t keepalive_timeout;    // REDIS_KEEPALIVE_TIMEOUT (мс)
    ngx_uint_t keepalive_poolsize;   // REDIS_KEEPALIVE_POOLSIZE
    ngx_uint_t poolsize;             // REDIS_POOLSIZE

} ngx_http_gkstat_redis_conf_t;
typedef struct {
    ngx_shm_zone_t *shm_zone;           // Shared memory zone for ngx_http_gatekeeper_global_stats_t
    ngx_uint_t stats_ttl;               // TTL for Redis writes (in seconds)
    ngx_http_gkstat_redis_conf_t redis; // Redis connection parameters
    redisContext **redis_pool;          // Redis Connection Pool
    ngx_uint_t redis_pool_size;         // Current pool size
} ngx_http_gkstat_conf_t;


#endif //NGX_HTTP_GK5Z_MODULE_STRUCT_H