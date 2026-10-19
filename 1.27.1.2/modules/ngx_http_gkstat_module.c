/*
 * @file    ngx_http_gkstat_module.c
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
#include <stdint.h>
#include <ngx_string.h>
#include <ngx_slab.h>
#include <ngx_event.h>
#include <hiredis/hiredis.h>
#include <stdio.h>
#include <string.h>
#include <ngx_conf_file.h> // for ngx_get_conf
#include <ngx_time.h>
#include <ngx_event_connect.h>
#include <ngx_http_lua_api.h> // Connecting our extended API
#include <ngx_http_lua_common.h>
#include "ngx_http_gkstat_module.h"
#include "ngx_gatekeeper_struct.h"
#include "ngx_http_redis_pool.h"

extern volatile ngx_cycle_t *ngx_cycle;

//Global variable for ClientHello error counter
ngx_shm_zone_t *ngx_gkstat_shm_zone_ptr = NULL;
//Global variable for the ClientHello #SHM error counter
static ngx_shm_zone_t *anomaly_counters_zone = NULL;
static ngx_shm_zone_t *gatekeeper_settings_zone = NULL;

// Defining Module Commands
static ngx_command_t ngx_http_gkstat_commands[] = {
    {
        ngx_string("gatekeeper_stats_shm"),
        NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE2,
        ngx_http_gkstat_shm,
        NGX_HTTP_MAIN_CONF_OFFSET,
        0,
        NULL
    },
    ngx_null_command
};

// Module context
static ngx_http_module_t ngx_http_gkstat_module_ctx = {
    NULL,                              // preconfiguration
    ngx_http_gkstat_postconfiguration, // postconfiguration
    ngx_http_gkstat_create_conf,       // create main configuration
    NULL,                              // init main configuration
    NULL,                              // create server configuration
    NULL,                              // merge server configuration
    NULL,                              // create location configuration
    NULL                               // merge location configuration
};

// Module Definition
ngx_module_t ngx_http_gkstat_module = {
    NGX_MODULE_V1,
    &ngx_http_gkstat_module_ctx,       // module context
    ngx_http_gkstat_commands,          // module directives
    NGX_HTTP_MODULE,                   // module type
    NULL,                              // init master
    NULL,                              // init module
    ngx_http_gkstat_init_process,      // init process
    NULL,                              // init thread
    NULL,                              // exit thread
    NULL,                              // exit process
    NULL,                              // exit master
    NGX_MODULE_V1_PADDING
};
//--------------------------------------------------------------
// Creating a module configuration
static void *ngx_http_gkstat_create_conf(ngx_conf_t *cf) {
    ngx_http_gkstat_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_gkstat_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->shm_zone = NULL;
    conf->stats_ttl = NGX_CONF_UNSET_UINT;

    return conf;
}
//--------------------------------------------------------------
// Creating a Shared Memory Zone
static ngx_int_t ngx_http_gkstat_init_shm_zone(ngx_shm_zone_t *shm_zone, void *data) {
    ngx_slab_pool_t *shpool;
    ngx_http_gatekeeper_global_stats_t *stats;

    if (data) {
        shm_zone->data = data;
        return NGX_OK;
    }

    shpool = (ngx_slab_pool_t *)shm_zone->shm.addr;

    stats = ngx_slab_alloc(shpool, sizeof(ngx_http_gatekeeper_global_stats_t));
    if (stats == NULL) {
        return NGX_ERROR;
    }

    stats->requests_cum = 0;
    stats->errors_4xx = 0;
    stats->errors_5xx = 0;
    stats->hello_error_count = 0;
    stats->min_time_req = NGX_MAX_UINT32_VALUE;
    stats->max_time_req = 0;

    ngx_log_error(NGX_LOG_DEBUG, ngx_cycle->log, 0, "Shared memory initialized: requests_cum=%uL, errors_4xx=%uL, errors_5xx=%uL",
                  stats->requests_cum, stats->errors_4xx, stats->errors_5xx);

    shm_zone->data = stats;
    return NGX_OK;
}
//--------------------------------------------------------------
// Command to set the shared memory size
static char *ngx_http_gkstat_shm(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_http_gkstat_conf_t *gkcf = conf;
    ngx_str_t *value;
    ngx_shm_zone_t *shm_zone;
    size_t size;

    value = cf->args->elts;

    size = ngx_parse_size(&value[2]);
    if ((int)size == NGX_ERROR || (int)size < 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid shared memory size: %V", &value[2]);
        return NGX_CONF_ERROR;
    }

    shm_zone = ngx_shared_memory_add(cf, &value[1], size, &ngx_http_gkstat_module);
    if (shm_zone == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "failed to add shared memory zone: %V", &value[1]);
        return NGX_CONF_ERROR;
    }

    shm_zone->init = ngx_http_gkstat_init_shm_zone;
    gkcf->shm_zone = shm_zone;

    ngx_conf_log_error(NGX_LOG_INFO, cf, 0, "shared memory zone created: %V, size: %uz", &value[1], size);

    return NGX_CONF_OK;
}
//--------------------------------------------------------------
// Handler for NGX_HTTP_ACCESS_PHASE
static ngx_int_t ngx_http_gkstat_access_handler(ngx_http_request_t *r) {
    ngx_http_gkstat_ctx_t *ctx;

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_gkstat_ctx_t));
    if (ctx == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "gkstat: failed to allocate ctx");
        return NGX_OK; // or NGX_ERROR if it is critical
    }
    
    // Get the current time in milliseconds from the Nginx cache
    ctx->request_start_msec = ngx_current_msec;

    ngx_http_set_ctx(r, ctx, ngx_http_gkstat_module);

    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                  "gkstat: access phase, start_msec=%M, uri=%V",
                  ctx->request_start_msec, &r->uri);

    return NGX_OK;
}
//--------------------------------------------------------------
// Timer function
static void ngx_http_gkstat_timer_handler(ngx_event_t *ev) {
    ngx_http_gkstat_conf_t *gkcf = ev->data;
    ngx_http_gatekeeper_global_stats_t *global_stats;  //1
    ngx_http_stats_t stats;
    u_char key[64];
    size_t key_len;
    ngx_time_t *tp;
    redisContext *redis;
    redisReply *reply;

    // We check that we are the only worker writing to Redis.
    if (ngx_process_slot != 0) {
        ngx_log_error(NGX_LOG_DEBUG, ev->log, 0, "Timer skipped: not main worker (slot=%i)", ngx_process_slot);
        ev->timedout = 0;
        ngx_add_timer(ev, 1000);
        return;
    }

//    ngx_log_error(NGX_LOG_DEBUG, ev->log, 0, "Timer handler called, worker slot=%i", ngx_process_slot);

    global_stats = (ngx_http_gatekeeper_global_stats_t *)gkcf->shm_zone->data;
    
    // We get a connection to Redis ONCE at the beginning
    redis = ngx_http_redis_pool_get_conn(gkcf, ev->log);
    if (redis == NULL) {
        ngx_log_error(NGX_LOG_WARN, ev->log, 0, "failed to get Redis connection, retrying in 1s");
        ev->timedout = 0;
        ngx_add_timer(ev, 1000);
        return;
    }
// =========================================================================
//         BLOCK 1: PROCESSING ANOMALIES FROM THE RING BUFFER
// =========================================================================
    if (global_stats != NULL) {
        // We check that we have successfully connected to the SHM zone at startup.
        if (anomaly_counters_zone != NULL) {
        
            ngx_uint_t anomalies_processed = 0;
    
            // We get the current read and write positions atomically.
            ngx_atomic_uint_t r_pos = global_stats->read_pos;
            ngx_atomic_uint_t w_pos = global_stats->write_pos;
    
            long anomaly_ttl_ms = 600; // Default value in case SHM is empty
            ngx_http_lua_value_t ttl_value;
            ngx_str_t ttl_key = ngx_string("anomaly_ttl");
            // Getting the TTL value of anomaly records from the config
            // Important: If we expect a string, we need to provide a buffer.
            u_char ttl_buffer[16];
            ttl_value.value.s.data = ttl_buffer;
            ttl_value.value.s.len = sizeof(ttl_buffer) - 1;

            if (get_setting_from_shm(ev->log, &ttl_key, &ttl_value) == NGX_OK) {
                if (ttl_value.type == LUA_TNUMBER) {
                    anomaly_ttl_ms = (long)ttl_value.value.n * 60 * 1000; // minutes -> ms
                } else if (ttl_value.type == LUA_TSTRING) {
                    ttl_buffer[ttl_value.value.s.len] = '\0';
                    anomaly_ttl_ms = atol((const char *)ttl_buffer) * 60 * 1000; // minutes -> ms
                }
            }
            long init_ttl = anomaly_ttl_ms;

            // We process all new records in the buffer that have accumulated by the time the timer starts.
            for (; r_pos < w_pos; r_pos++) {

                // A safety feature to prevent the worker from being blocked for a long time
                if (anomalies_processed >= ANOMALY_BUFFER_SIZE) {
                    ngx_log_error(NGX_LOG_WARN, ev->log, 0, 
                              "[GK-STAT] Anomaly buffer processing limit reached (%d), will continue on next timer run.",
                              ANOMALY_BUFFER_SIZE);
                    break; 
                }

                ngx_uint_t pos_to_read = r_pos % ANOMALY_BUFFER_SIZE;
                ngx_anomaly_entry_t *entry = &global_stats->buffer[pos_to_read];

                char ip_hex_str[IP_HEX_STR_LEN];
                ngx_memzero(ip_hex_str, IP_HEX_STR_LEN); // Guaranteed buffer cleaning

                // ---IP CONVERSION ---
                if (entry->ip_type == 1) {
                    uint32_t ip_host_order = ntohl(entry->addr.v4);
                    snprintf(ip_hex_str, IP_HEX_STR_LEN, "%08lx", (unsigned long)ip_host_order);
                } else if (entry->ip_type == 2) {
                    char *p = ip_hex_str;
                    size_t remaining_space = IP_HEX_STR_LEN;
                    int written_chars;

                    for (int i = 0; i < 16; i++) {
                        if (remaining_space < 3) { break; }
                        written_chars = snprintf(p, remaining_space, "%02x", entry->addr.v6[i]);
                        if (written_chars < 0 || (size_t)written_chars >= remaining_space) { *p = '\0'; break; }
                        p += written_chars;
                        remaining_space -= written_chars;
                    }
                }
                // --- END OF CONVERSION ---

                if (ip_hex_str[0] == '\0') {
                     ngx_log_error(NGX_LOG_WARN, ev->log, 0, "[GK-STAT] Failed to convert IP for anomaly entry at pos %ui. Skipping.", pos_to_read);
                     anomalies_processed++;
                     continue; // Skip this entry
                }

                ngx_log_debug(NGX_LOG_DEBUG, ev->log, 0, 
                          "[GK-STAT] Processing anomaly: pos=%ui, ip_type=%d, reason=%d, ip_hex='%s'",
                          pos_to_read, entry->ip_type, entry->reason, ip_hex_str);

                // 1. Generating a key for SHM: "an:<hex_ip>:<reason_id>"
                u_char key[128];
                size_t key_len;
                key_len = ngx_snprintf(key, sizeof(key), "an:%s:%d", ip_hex_str, (int)entry->reason) - key;

                // 2. Preparing parameters for calling shdict:incr
                double      incr_by = 1.0;
                double      init_val = 0.0;
                char       *err_msg = NULL;
                int         forcible = 0;

                // 3. Calling the C API to increment SHM
                ngx_int_t rc = ngx_http_lua_ffi_shdict_incr(
                    anomaly_counters_zone,
                    key,
                    key_len,
                    &incr_by,
                    &err_msg,
                    1,          // has_init = 1 (create if not present)
                    init_val,
                    init_ttl,
                    &forcible
                );

                // 4. Logging the result
                if (rc != NGX_OK) {
                    ngx_log_error(NGX_LOG_ERR, ev->log, 0, 
                              "[GK-STAT] SHDICT INCR FAILED for key '%*s'. Error: %s", 
                              key_len, key, err_msg ? (const char *)err_msg : "Unknown error");
                }

                anomalies_processed++;
            }

            // After the loop, if we have processed anything, we atomically shift the global read pointer
            if (anomalies_processed > 0) {
                ngx_atomic_uint_t current_r_pos;
                // Using a compare-and-swap cycle for 100% reliable updates
                do {
                    current_r_pos = global_stats->read_pos;
                } while (!ngx_atomic_cmp_set(&global_stats->read_pos, current_r_pos, r_pos));

                ngx_log_debug(NGX_LOG_DEBUG, ev->log, 0, 
                          "[GK-STAT] %ui anomalies processed. SHM read_pos advanced to %P", 
                          anomalies_processed, global_stats->read_pos);
            }
        } else {
            ngx_log_debug(NGX_LOG_DEBUG, ev->log, 0, 
                      "[GK-STAT] Anomaly processing skipped: shm_zone not found.");
        }
    }
    // =========================================================================
    //         BLOCK 2: SENDING GENERAL STATISTICS
    // =========================================================================
    ngx_memzero(&stats, sizeof(ngx_http_stats_t));
    
    // Initializing statistics
    stats.active_connections = ngx_stat_active ? *ngx_stat_active : 0;
    stats.waiting_connections = ngx_stat_waiting ? *ngx_stat_waiting : 0;
    stats.accepted_connections = ngx_stat_accepted ? *ngx_stat_accepted : 0;
    stats.handled_connections = ngx_stat_handled ? *ngx_stat_handled : 0;
    stats.reading = ngx_stat_reading ? *ngx_stat_reading : 0;
    stats.writing = ngx_stat_writing ? *ngx_stat_writing : 0;
    stats.requests_total = ngx_stat_requests ? *ngx_stat_requests : 0; //For the general counter - uint64_t
    stats.requests_cum = global_stats->requests_cum; //For a per-second counter - uint32_t
    stats.errors_4xx = global_stats->errors_4xx;
    stats.errors_5xx = global_stats->errors_5xx;
    stats.min_time_req = global_stats->min_time_req == NGX_MAX_UINT32_VALUE ? 0 : global_stats->min_time_req;
    stats.max_time_req = global_stats->max_time_req;
    stats.hello_error_count = global_stats->hello_error_count;
    stats.hello_error_total = global_stats->total_hello_error_count;

    ngx_core_conf_t *ccf; // Variable for storing core configuration
    ccf = (ngx_core_conf_t *) ngx_get_conf(ngx_cycle->conf_ctx, ngx_core_module);

    if (ccf) { // Let's add a NULL check just in case.
        ngx_uint_t num_workers = ccf->worker_processes;
        stats.workers_count = num_workers;
//        ngx_log_error(NGX_LOG_DEBUG, ev->log, 0, "Number of worker processes: %ui", num_workers);
    }

    // Forming a key
    tp = ngx_timeofday();
    key_len = ngx_snprintf(key, sizeof(key), "stats:%T", tp->sec) - key;
    
    // We send general statistics
    reply = redisCommand(redis, "SETEX %b %d %b", key, key_len, gkcf->stats_ttl, &stats, sizeof(ngx_http_stats_t));
    if (reply) {
        if (reply->type == REDIS_REPLY_ERROR) {
             ngx_log_error(NGX_LOG_WARN, ev->log, 0, "Redis SETEX for stats error: %s", reply->str);
        }
        freeReplyObject(reply);
    } else {
        ngx_log_error(NGX_LOG_WARN, ev->log, 0, "Redis SETEX for stats failed: %s", redis->errstr);
    }

    // =========================================================================
    //         BLOCK 3: RESET COUNTERS AND TERMINATION
    // =========================================================================

    // Returning the connection to the pool
    ngx_http_redis_pool_put_conn(gkcf, redis);

    // Resetting global statistics
    if (global_stats != NULL) {
        global_stats->requests_cum = 0;
        global_stats->errors_4xx = 0;
        global_stats->errors_5xx = 0;
        global_stats->hello_error_count = 0;
        global_stats->min_time_req = NGX_MAX_UINT32_VALUE;
        global_stats->max_time_req = 0;
    }
  
    // Restart the timer
    ev->timedout = 0;
    ngx_add_timer(ev, 1000);
}
//--------------------------------------------------------------
// Initializing the process
static ngx_int_t ngx_http_gkstat_init_process(ngx_cycle_t *cycle)
{
    ngx_http_gkstat_conf_t *gkcf;
    ngx_event_t            *ev;

    // --- Block 1: Initialization of SHM zones ---
    // To calculate anomalies
    ngx_str_t counters_zone_name = ngx_string("anomaly_counters");
    anomaly_counters_zone = ngx_http_lua_find_zone(counters_zone_name.data, counters_zone_name.len);
    if (anomaly_counters_zone == NULL) {
        ngx_log_error(NGX_LOG_WARN, cycle->log, 0, 
                      "gkstat: lua_shared_dict_zone 'anomaly_counters' not found. Anomaly detection will be disabled.");
    }

    // For settings
    ngx_str_t settings_zone_name = ngx_string("settings");
    gatekeeper_settings_zone = ngx_http_lua_find_zone(settings_zone_name.data, settings_zone_name.len);
    if (gatekeeper_settings_zone == NULL) {
        ngx_log_error(NGX_LOG_WARN, cycle->log, 0, 
                      "gkstat: lua_shared_dict_zone 'settings' not found. Settings will be defaults.");
    }

    // --- Block 2: Initializing the pointer for the SSL patch ---
    gkcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_gkstat_module);
    if (gkcf != NULL && gkcf->shm_zone != NULL) {
        ngx_gkstat_shm_zone_ptr = gkcf->shm_zone;
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, cycle->log, 0, "gkstat: global shm pointer for ssl patch initialized");
    }

    // --- Block 3: Initializing the Redis Pool (CRITICAL) ---
    if (gkcf == NULL) {
        ngx_log_error(NGX_LOG_CRIT, cycle->log, 0, "gkstat: Could not get module main conf.");
        return NGX_ERROR; // If there is no config, there is no point in continuing to work.
    }
    if (ngx_http_redis_pool_parse_ini(cycle, gkcf) != NGX_OK) {
        ngx_log_error(NGX_LOG_CRIT, cycle->log, 0, "gkstat: Failed to initialize Redis pool.");
        return NGX_ERROR; // If there is no Redis, the timer will have nothing to work with.
    }

    // --- Block 4: Starting the timer (for worker 0 only) ---
    if (ngx_process_slot == 0) {
        ev = ngx_pcalloc(cycle->pool, sizeof(ngx_event_t));
        if (ev == NULL) {
            ngx_log_error(NGX_LOG_CRIT, cycle->log, 0, "gkstat: Failed to allocate memory for timer event.");
            return NGX_ERROR;
        }

        ev->handler = ngx_http_gkstat_timer_handler;
        ev->data = gkcf;
        ev->log = cycle->log;

        ngx_add_timer(ev, 1000);
        ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "gkstat: Anomaly processing timer started for worker 0.");
    }
    
    return NGX_OK; // Successful completion for all workers
}
//--------------------------------------------------------------
/*
 * A general-purpose function for reading values ​​from SHM 'settings'.
 *
 * @param log       Pointer to Nginx log.
 * @param key       Configuration key (for example, "anomaly_ttl").
 * @param value     Pointer to the ngx_http_lua_value_t structure where the result will be written.
 *                  For string values, value->value.s.data must be pre-allocated.
 * @return          NGX_OK on success, NGX_ERROR/NGX_DECLINED on error.
 */
static ngx_int_t
get_setting_from_shm(ngx_log_t *log, ngx_str_t *key, ngx_http_lua_value_t *value)
{
    if (gatekeeper_settings_zone == NULL) {
        // We don't log here to avoid spam. The calling code will decide what to do.
        return NGX_ERROR;
    }

    ngx_int_t rc;
    // 1. We are generating a complete key for configuration
    u_char full_key[128]; // Full Key Buffer
//    ngx_snprintf(full_key, sizeof(full_key), "v%s_settings_%V%Z", index_buffer2, key);
    ngx_snprintf(full_key, sizeof(full_key), "settings_%V%Z", key);

    // 2. Reading the value using the full key
    rc = ngx_http_lua_shared_dict_get(gatekeeper_settings_zone, full_key, ngx_strlen(full_key), value);
    
    if (rc != NGX_OK) {
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, log, 0, 
                      "[GK-STAT] Settings: Key '%s' not found in SHM.", full_key);
        return rc; // NGX_DECLINED or NGX_DONE
    }

    return NGX_OK;
}
//--------------------------------------------------------------
// Handler for NGX_HTTP_LOG_PHASE
static ngx_int_t ngx_http_gkstat_log_handler(ngx_http_request_t *r) {
    ngx_http_gkstat_ctx_t *ctx;
    ngx_msec_t req_time;
    ngx_http_gkstat_conf_t *gkcf;
    ngx_http_gatekeeper_global_stats_t *global_stats;
    ngx_atomic_uint_t old_val;

    // We get the module configuration where the pointer to shm_zone is stored
    gkcf = ngx_http_get_module_main_conf(r, ngx_http_gkstat_module);
    if (gkcf == NULL || gkcf->shm_zone == NULL) {
        return NGX_OK;
    }

    // We get a pointer to a structure in shared memory
    global_stats = (ngx_http_gatekeeper_global_stats_t *)gkcf->shm_zone->data;

    // 1. Incrementing the total request counter
    (void) ngx_atomic_fetch_add(&global_stats->requests_cum, 1);
    
    // 2. We check the response code and increment the error counters
    if (r->headers_out.status >= 500) {
        (void) ngx_atomic_fetch_add(&global_stats->errors_5xx, 1);
    } else if (r->headers_out.status >= 400) {
        (void) ngx_atomic_fetch_add(&global_stats->errors_4xx, 1);
    }

    // 3. Calculating query execution time
    ctx = ngx_http_get_module_ctx(r, ngx_http_gkstat_module);
    if (ctx == NULL || ctx->request_start_msec == 0) {
        // If there is no context, we cannot calculate time.
        return NGX_OK;
    }

    // ngx_current_msec is also cached, so it is a fast operation
    req_time = ngx_current_msec - ctx->request_start_msec;

    // Protection against strange values ​​(for example, if time has shifted backwards)
    if ((ngx_msec_int_t) req_time < 0) {
        req_time = 0;
    }

    // Updating min_time_req
    // This is a compare-and-swap loop. It ensures that we update the value,
    // only if it has not been changed by another worker during our check.
    do {
        old_val = global_stats->min_time_req;
        if (req_time >= old_val) {
            break; // Our time is no less, let's go out
        }
    } while (!ngx_atomic_cmp_set(&global_stats->min_time_req, old_val, req_time));

    // Updating max_time_req
    do {
        old_val = global_stats->max_time_req;
        if (req_time <= old_val) {
            break; // Our time is no more, let's go out
        }
    } while (!ngx_atomic_cmp_set(&global_stats->max_time_req, old_val, req_time));

    return NGX_OK;
}
//--------------------------------------------------------------
// Registering handlers
static ngx_int_t
ngx_http_gkstat_postconfiguration(ngx_conf_t *cf)
{
    ngx_http_handler_pt *h;
    ngx_http_core_main_conf_t *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    if (cmcf == NULL) {
        return NGX_ERROR;
    }

    // Register a handler for NGX_HTTP_ACCESS_PHASE
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }
    *h = ngx_http_gkstat_access_handler;

    // Register a handler for NGX_HTTP_LOG_PHASE
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_LOG_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }
    *h = ngx_http_gkstat_log_handler;

    // Tell ngx_lua: "When someone asks for 'gatekeeper_c_api',
    // call my C function luaopen_gatekeeper_c_api".
    ngx_http_lua_add_package_preload(cf, "gatekeeper_c_api", luaopen_gatekeeper_c_api);

    ngx_log_error(NGX_LOG_INFO, cf->log, 0, "gkstat: access and log handlers registered");

    return NGX_OK;
}
//--------------------------------------------------------------
int
ngx_http_gkstat_lua_get_hello_details(lua_State *L)
{
    ngx_http_request_t *r;
    ngx_connection_t   *c;
    SSL                *s;

    // 1. We receive a "fake" http request that ngx_lua creates for
    //    early phases to extract the connection pointer from it.
    //    This is the most reliable way to get context in ssl_client_hello.
    r = ngx_http_lua_get_request(L);
    if (r == NULL) {
        lua_pushnil(L);
        lua_pushstring(L, "could not get request context from Lua");
        return 2;
    }

    c = r->connection;

    // 2. We check that we have a valid SSL context.
    if (c == NULL || c->ssl == NULL || c->ssl->connection == NULL) {
        lua_pushnil(L);
        lua_pushstring(L, "not a valid SSL connection");
        return 2;
    }

    // 3. We get a "raw" OpenSSL SSL object containing the resumption flag.
    s = c->ssl->connection;

    // 4. We create a new table on the Lua stack, which we will return.
    lua_newtable(L);

    // 5. Fill the table with data from your patched c->ssl->... structure.

    // Adding the client's IP address
    lua_pushstring(L, "remote_addr");
    lua_pushlstring(L, (const char *)c->addr_text.data, c->addr_text.len);
    lua_settable(L, -3);
    
    // --- Session resume flag (most important) ---
    lua_pushstring(L, "is_resumption");
    lua_pushboolean(L, SSL_session_reused(s));
    lua_settable(L, -3);

    // --- ALPN ---
    if (c->ssl->client_alpns != NULL) {
        lua_pushstring(L, "alpn");
        lua_pushstring(L, c->ssl->client_alpns);
        lua_settable(L, -3);
    }

    // --- Number of ciphers ---
    lua_pushstring(L, "ciphers_count");
    lua_pushinteger(L, c->ssl->ciph_sz);
    lua_settable(L, -3);

    // --- Number of extensions ---
    lua_pushstring(L, "extensions_count");
    lua_pushinteger(L, c->ssl->extn_sz);
    lua_settable(L, -3);

    // --- Number of supported versions ---
    lua_pushstring(L, "supported_versions_count");
    lua_pushinteger(L, c->ssl->supp_vers_sz);
    lua_settable(L, -3);

    // --- Number of supported groups ---
    lua_pushstring(L, "supported_groups_count");
    lua_pushinteger(L, c->ssl->supp_groups_sz);
    lua_settable(L, -3);

    // ...if necessary, you can add any other fields from c->ssl here...
    
    // 6. Our table remains on the top of the stack. Let's return it.
    return 1;
}
//--------------------------------------------------------------
// 2. Module loader. This function will be called when Lua calls require("gatekeeper_c_api").
//    It creates and returns a table with our C functions.
static int
luaopen_gatekeeper_c_api(lua_State *L)
{
    // Create a method table
    static const luaL_Reg methods[] = {
        { "get_hello_details", ngx_http_gkstat_lua_get_hello_details },
        { NULL, NULL } // The final element
    };

    // Create a new library (Lua table) with these methods
    luaL_newlib(L, methods);

    return 1; // We return 1 value (the table module itself)
}
//--------------------------------------------------------------
