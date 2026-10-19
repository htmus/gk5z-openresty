/*
 * @file    ngx_http_redis_pool.h
 * @project GATEKEEPER WAF (GK5Z Engine)
 * @brief   High-performance TLS Session Fingerprinting and Anomaly Detection
 * @date    19.10.2026
 *
 * @copyright (c) 2026 GATEKEEPER Project
 * @license   GNU General Public License v3.0 (GPLv3)
 * @see       github.com/htmus/gk5z-openresty
 */

#ifndef NGX_HTTP_REDIS_POOL_H
#define NGX_HTTP_REDIS_POOL_H

// Prototypes of "public" functions
redisContext* ngx_http_redis_pool_get_conn(ngx_http_gkstat_conf_t *gkcf, ngx_log_t *log);
void ngx_http_redis_pool_put_conn(ngx_http_gkstat_conf_t *gkcf, redisContext *redis);
ngx_int_t ngx_http_redis_pool_parse_ini(ngx_cycle_t *cycle, ngx_http_gkstat_conf_t *gkcf);

#endif