/*
 * @file    ngx_http_redis_pool.c
 * @project GATEKEEPER WAF (GK5Z Engine)
 * @brief   High-performance TLS Session Fingerprinting and Anomaly Detection
 * @date    19.10.2026
 *
 * @copyright (c) 2026 GATEKEEPER Project
 * @license   GNU General Public License v3.0 (GPLv3)
 * @see       github.com/htmus/gk5z-openresty
 */

#include <ngx_config.h>
#include <stdio.h>
#include <string.h>
#include "ngx_gatekeeper_struct.h"
#include "ngx_http_redis_pool.h"

// Parsing an INI file
ngx_int_t ngx_http_redis_pool_parse_ini(ngx_cycle_t *cycle, ngx_http_gkstat_conf_t *gkcf) {
    FILE *fp;
    char line[256];
    char *trimmed, *key, *value, *comment;
    u_char *end;
    char config_path[256];
    char *base_dir = getenv("GATEKEEPER_BASE");

    // Forming a path to the configuration file
    if (base_dir == NULL) {
        base_dir = "/usr/local/openresty"; // Default path
        ngx_log_error(NGX_LOG_WARN, cycle->log, 0, "GATEKEEPER_BASE not set, using default: %s", base_dir);
    }
    snprintf(config_path, sizeof(config_path), "%s/config/gtk.conf", base_dir);

    // Setting up default Redis parameters
    gkcf->redis.host.data = ngx_pcalloc(cycle->pool, strlen("127.0.0.1") + 1);
    if (gkcf->redis.host.data == NULL) {
        return NGX_ERROR;
    }
    ngx_cpystrn(gkcf->redis.host.data, (u_char *)"127.0.0.1", strlen("127.0.0.1") + 1);
    gkcf->redis.host.len = strlen("127.0.0.1");
    gkcf->redis.port = 6379;
    gkcf->redis.passwd.data = NULL;
    gkcf->redis.passwd.len = 0;
    gkcf->redis.dbindex = 0;
    gkcf->redis.connect_timeout = 1000;
    gkcf->redis.send_timeout = 1000;
    gkcf->redis.read_timeout = 1000;
    gkcf->redis.keepalive_timeout = 60000;
    gkcf->redis.keepalive_poolsize = 10;
    gkcf->redis.poolsize = 100;
    gkcf->stats_ttl = 600;  //10 минут

    // Let's try to open the configuration file
    fp = fopen(config_path, "r");
    if (fp != NULL) {
    // Parsing the configuration file
        while (fgets(line, sizeof(line), fp)) {
            trimmed = line;
            while (*trimmed == ' ' || *trimmed == '\t') trimmed++;
            end = (u_char *)trimmed + strlen(trimmed);
            while (end > (u_char *)trimmed && (*(end-1) == ' ' || *(end-1) == '\t' || *(end-1) == '\n' || *(end-1) == '\r')) end--;
            *end = '\0';

            if (strlen(trimmed) == 0 || trimmed[0] == '#' || trimmed[0] == '[') continue;

            comment = strchr(trimmed, '#');
            if (comment) {
                while (comment > trimmed && (*(comment-1) == ' ' || *(comment-1) == '\t')) comment--;
                *comment = '\0';
            }

            key = trimmed;
            value = strchr(trimmed, '=');
            if (value == NULL) continue;
            *value++ = '\0';

            while (*key == ' ' || *key == '\t') key++;
            end = (u_char *)key + strlen(key);
            while (end > (u_char *)key && (*(end-1) == ' ' || *(end-1) == '\t')) end--;
            *end = '\0';

            while (*value == ' ' || *value == '\t') value++;
            end = (u_char *)value + strlen(value);
            while (end > (u_char *)value && (*(end-1) == ' ' || *(end-1) == '\t')) end--;
            *end = '\0';

            if (strcmp(key, "REDIS_HOST") == 0) {
                if (gkcf->redis.host.data) {
                    ngx_pfree(cycle->pool, gkcf->redis.host.data);
                }
                gkcf->redis.host.data = ngx_pcalloc(cycle->pool, strlen(value) + 1);
                if (gkcf->redis.host.data == NULL) {
                    fclose(fp);
                    return NGX_ERROR;
                }
                ngx_cpystrn(gkcf->redis.host.data, (u_char *)value, strlen(value) + 1);
                gkcf->redis.host.len = strlen(value);
            } else if (strcmp(key, "REDIS_PORT") == 0) {
                gkcf->redis.port = ngx_atoi((u_char *)value, strlen(value));
                if ((int)gkcf->redis.port == NGX_ERROR || (int)gkcf->redis.port < 0) {
                    ngx_log_error(NGX_LOG_WARN, cycle->log, 0, "invalid REDIS_PORT value: %s, using default: %d", value, gkcf->redis.port);
                }
            } else if (strcmp(key, "REDIS_PASSWD") == 0) {
                if (gkcf->redis.passwd.data) {
                    ngx_pfree(cycle->pool, gkcf->redis.passwd.data);
                }
                gkcf->redis.passwd.data = ngx_pcalloc(cycle->pool, strlen(value) + 1);
                if (gkcf->redis.passwd.data == NULL) {
                    fclose(fp);
                    return NGX_ERROR;
                }
                ngx_cpystrn(gkcf->redis.passwd.data, (u_char *)value, strlen(value) + 1);
                gkcf->redis.passwd.len = strlen(value);
            } else if (strcmp(key, "REDIS_DBINDEX") == 0) {
                gkcf->redis.dbindex = ngx_atoi((u_char *)value, strlen(value));
                if ((int)gkcf->redis.dbindex == NGX_ERROR || (int)gkcf->redis.dbindex < 0) {
                    ngx_log_error(NGX_LOG_WARN, cycle->log, 0, "invalid REDIS_DBINDEX value: %s, using default: %d", value, gkcf->redis.dbindex);
                }
            } else if (strcmp(key, "REDIS_CONNECT_TIMEOUT") == 0) {
                gkcf->redis.connect_timeout = ngx_atoi((u_char *)value, strlen(value));
                if ((int)gkcf->redis.connect_timeout == NGX_ERROR || (int)gkcf->redis.connect_timeout <= 0) {
                    ngx_log_error(NGX_LOG_WARN, cycle->log, 0, "invalid REDIS_CONNECT_TIMEOUT value: %s, using default: %d", value, gkcf->redis.connect_timeout);
                }
            } else if (strcmp(key, "REDIS_SEND_TIMEOUT") == 0) {
                gkcf->redis.send_timeout = ngx_atoi((u_char *)value, strlen(value));
                if ((int)gkcf->redis.send_timeout == NGX_ERROR || (int)gkcf->redis.send_timeout <= 0) {
                    ngx_log_error(NGX_LOG_WARN, cycle->log, 0, "invalid REDIS_SEND_TIMEOUT value: %s, using default: %d", value, gkcf->redis.send_timeout);
                }
            } else if (strcmp(key, "REDIS_READ_TIMEOUT") == 0) {
                gkcf->redis.read_timeout = ngx_atoi((u_char *)value, strlen(value));
                if ((int)gkcf->redis.read_timeout == NGX_ERROR || (int)gkcf->redis.read_timeout <= 0) {
                    ngx_log_error(NGX_LOG_WARN, cycle->log, 0, "invalid REDIS_READ_TIMEOUT value: %s, using default: %d", value, gkcf->redis.read_timeout);
                }
            } else if (strcmp(key, "REDIS_KEEPALIVE_TIMEOUT") == 0) {
                gkcf->redis.keepalive_timeout = ngx_atoi((u_char *)value, strlen(value));
                if ((int)gkcf->redis.keepalive_timeout == NGX_ERROR || (int)gkcf->redis.keepalive_timeout <= 0) {
                    ngx_log_error(NGX_LOG_WARN, cycle->log, 0, "invalid REDIS_KEEPALIVE_TIMEOUT value: %s, using default: %d", value, gkcf->redis.keepalive_timeout);
                }
            } else if (strcmp(key, "REDIS_KEEPALIVE_POOLSIZE") == 0) {
                gkcf->redis.keepalive_poolsize = ngx_atoi((u_char *)value, strlen(value));
                if ((int)gkcf->redis.keepalive_poolsize == NGX_ERROR || (int)gkcf->redis.keepalive_poolsize <= 0) {
                    ngx_log_error(NGX_LOG_WARN, cycle->log, 0, "invalid REDIS_KEEPALIVE_POOLSIZE value: %s, using default: %d", value, gkcf->redis.keepalive_poolsize);
                }
            } else if (strcmp(key, "REDIS_POOLSIZE") == 0) {
                gkcf->redis.poolsize = ngx_atoi((u_char *)value, strlen(value));
                if ((int)gkcf->redis.poolsize == NGX_ERROR || (int)gkcf->redis.poolsize <= 0) {
                    ngx_log_error(NGX_LOG_WARN, cycle->log, 0, "invalid REDIS_POOLSIZE value: %s, using default: %d", value, gkcf->redis.poolsize);
                }
            } else if (strcmp(key, "STATS_RECORDS_TTL") == 0) {
                gkcf->stats_ttl = ngx_atoi((u_char *)value, strlen(value));
                if ((int)gkcf->stats_ttl == NGX_ERROR || (int)gkcf->stats_ttl <= 0) {
                    ngx_log_error(NGX_LOG_WARN, cycle->log, 0, "invalid STATS_RECORDS_TTL value: %s, using default: %d", value, gkcf->stats_ttl);
                }
            }
        }
        fclose(fp);
    } else {
        ngx_log_error(NGX_LOG_WARN, cycle->log, errno, "failed to open config file: %s, using default Redis parameters", config_path);
    }
    // Initializing a connection pool
    gkcf->redis_pool = ngx_pcalloc(cycle->pool, sizeof(redisContext *) * gkcf->redis.poolsize);
    if (gkcf->redis_pool == NULL) {
        return NGX_ERROR;
    }
    gkcf->redis_pool_size = 0;

    // Checking the connection to Redis
    redisContext *redis = ngx_http_redis_pool_get_conn(gkcf, cycle->log);
    if (redis == NULL) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "failed to connect to Redis with parameters: host=%V, port=%d", &gkcf->redis.host, gkcf->redis.port);
        return NGX_ERROR;
    }
    ngx_http_redis_pool_put_conn(gkcf, redis);

    return NGX_OK;
}
//--------------------------------------------------------------
// Getting a connection from the pool
redisContext *ngx_http_redis_pool_get_conn(ngx_http_gkstat_conf_t *gkcf, ngx_log_t *log) {
    redisContext *redis = NULL;
    redisReply *reply;

    if (gkcf->redis_pool_size > 0) {
        gkcf->redis_pool_size--;
        redis = gkcf->redis_pool[gkcf->redis_pool_size];
        gkcf->redis_pool[gkcf->redis_pool_size] = NULL;

        // Check the connection before use
        reply = redisCommand(redis, "PING");
        if (reply == NULL || redis->err) {
            ngx_log_error(NGX_LOG_WARN, log, 0, "Redis PING failed, connection is dead: %s. Reconnecting...", redis->errstr);
            redisFree(redis);
            redis = NULL; // Set to NULL to create a new connection
        } else {
            freeReplyObject(reply);
            ngx_log_debug(NGX_LOG_DEBUG, log, 0, "Redis connection taken from pool and PING OK, size: %ui", gkcf->redis_pool_size);
            return redis;
        }
    }

    // If the connection from the pool is invalid or the pool is empty
    if (redis == NULL) {
        struct timeval timeout = { gkcf->redis.connect_timeout / 1000, (gkcf->redis.connect_timeout % 1000) * 1000 };
        redis = redisConnectWithTimeout((char *)gkcf->redis.host.data, gkcf->redis.port, timeout);
        if (redis == NULL || redis->err) {
            if (redis) {
                ngx_log_error(NGX_LOG_ERR, log, 0, "Redis connection error: %s", redis->errstr);
                redisFree(redis);
            } else {
                ngx_log_error(NGX_LOG_ERR, log, 0, "Failed to allocate Redis context");
            }
            return NULL;
        }

        if (gkcf->redis.passwd.len > 0) {
            reply = redisCommand(redis, "AUTH %s", gkcf->redis.passwd.data);
            if (reply == NULL || reply->type == REDIS_REPLY_ERROR) {
                ngx_log_error(NGX_LOG_ERR, log, 0, "Redis AUTH error: %s", reply ? reply->str : redis->errstr);
                if (reply) freeReplyObject(reply);
                redisFree(redis);
                return NULL;
            }
            freeReplyObject(reply);
        }

        reply = redisCommand(redis, "SELECT %d", gkcf->redis.dbindex);
        if (reply == NULL || reply->type == REDIS_REPLY_ERROR) {
            ngx_log_error(NGX_LOG_ERR, log, 0, "Redis SELECT error: %s", reply ? reply->str : redis->errstr);
            if (reply) freeReplyObject(reply);
            redisFree(redis);
            return NULL;
        }
        freeReplyObject(reply);

        redisSetTimeout(redis, (struct timeval){ gkcf->redis.read_timeout / 1000, (gkcf->redis.read_timeout % 1000) * 1000 });
        ngx_log_debug(NGX_LOG_DEBUG, log, 0, "New Redis connection created.");
    }

    return redis;
}
//--------------------------------------------------------------
// Returning a connection to the pool
void ngx_http_redis_pool_put_conn(ngx_http_gkstat_conf_t *gkcf, redisContext *redis) {
    if (redis == NULL) {
        return;
    }

    // We do not return "broken" connections to the pool
    if (redis->err) {
        ngx_log_error(NGX_LOG_WARN, ngx_cycle->log, 0, "Not returning broken Redis connection to pool (err: %d, errstr: %s)", redis->err, redis->errstr);
        redisFree(redis);
        return;
    }

    if (gkcf->redis_pool_size < gkcf->redis.poolsize) {
        gkcf->redis_pool[gkcf->redis_pool_size++] = redis;
        ngx_log_debug(NGX_LOG_DEBUG, ngx_cycle->log, 0, "Redis connection returned to pool, size: %ui", gkcf->redis_pool_size);
    } else {
        redisFree(redis);
        ngx_log_debug(NGX_LOG_DEBUG, ngx_cycle->log, 0, "Redis connection freed, pool full: %ui", gkcf->redis_pool_size);
    }
}
//--------------------------------------------------------------
