/*
 * @file    ngx_http_gkstat_module.h
 * @project GATEKEEPER WAF (GK5Z Engine)
 * @brief   High-performance TLS Session Fingerprinting and Anomaly Detection
 * @date    19.10.2026
 *
 * @copyright (c) 2026 GATEKEEPER Project
 * @license   GNU General Public License v3.0 (GPLv3)
 * @see       github.com/htmus/gk5z-openresty
 */

#ifndef NGX_HTTP_GKSTAT_MODULE_H
#define NGX_HTTP_GKSTAT_MODULE_H

#include <ngx_http.h>
#include <ngx_core.h>
#include <stdint.h>

#define IP_HEX_STR_LEN 40

typedef struct {
    ngx_msec_t request_start_msec;
} ngx_http_gkstat_ctx_t;

//To avoid confusion and keep the CPU happy, it's best to order the fields from largest to smallest (all uint64_t first, then uint32_t, and finally uint16_t and uint8_t). Then the natural alignment will match the packed one.
typedef struct {
    uint32_t active_connections;    // Number of active connections (ngx_stat_active)
    uint32_t waiting_connections;   // Number of keep-alive connections in idle mode (ngx_stat_waiting)
    uint64_t accepted_connections;  // Total number of accepted connections (ngx_stat_accepted) since startup
    uint64_t handled_connections;   // Number of successfully processed connections (ngx_stat_handled) since startup
    uint32_t reading;               // The number of connections in which Nginx is reading an HTTP request (ngx_stat_reading)
    uint32_t writing;               // The number of connections in which Nginx is writing an HTTP request (ngx_stat_writing)
    uint64_t requests_total;        // Total number of processed requests (ngx_stat_requests) since launch
    uint32_t requests_cum;          // Total number of requests processed per second
    uint32_t errors_4xx;            // Number of 4xx errors per second
    uint32_t errors_5xx;            // Number of 5xx errors per second
    uint32_t min_time_req;          // Minimum request processing time (in milliseconds)
    uint32_t max_time_req;          // Maximum request processing time (in milliseconds)
    uint32_t hello_error_count;     // Number of ClientHello errors per second
    uint64_t hello_error_total;     // Number of ClientHello errors since launch
    uint16_t workers_count;         // Number of workers
} __attribute__((packed)) ngx_http_stats_t; //Instructions not to align - otherwise it will be a mess

// Forward function declarations
static void *ngx_http_gkstat_create_conf(ngx_conf_t *cf);
static char *ngx_http_gkstat_shm(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_gkstat_init_shm_zone(ngx_shm_zone_t *shm_zone, void *data);
static void ngx_http_gkstat_timer_handler(ngx_event_t *ev);
static ngx_int_t ngx_http_gkstat_init_process(ngx_cycle_t *cycle);
static ngx_int_t ngx_http_gkstat_postconfiguration(ngx_conf_t *cf);
static ngx_int_t ngx_http_gkstat_access_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_gkstat_log_handler(ngx_http_request_t *r);
static ngx_int_t get_setting_from_shm(ngx_log_t *log, ngx_str_t *key, ngx_http_lua_value_t *value);
//Function for hello_by_lua
int ngx_http_gkstat_lua_get_hello_details(lua_State *L);
static int luaopen_gatekeeper_c_api(lua_State *L);
static ngx_int_t gk_shm_init(ngx_shm_zone_t *zone, void *data);

#endif