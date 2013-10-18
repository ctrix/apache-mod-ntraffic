/*
 * mod_ntraffic - Traffic statistics collector for Apache
 *
 * Copyright (C) 2008-2013, Massimo Cetra <massimo.cetra at gmail.com>
 *
 * Version: MPL 2
 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 1.1 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Original Code is mod_ntraffic
 *
 * The Initial Developer of the Original Code is
 * Massimo Cetra <massimo.cetra at gmail.com>
 *
 * Portions created by the Initial Developer are Copyright (C)
 * the Initial Developer. All Rights Reserved.
 *
 */

#include "mod_ntraffic.h"

module AP_MODULE_DECLARE_DATA ntraffic_module;

/****************************************************************************    
    MAIN VARIABLES
 ***************************************************************************/

static shm_pool_t *main_shmp = NULL;
static traffic_data_t *data_root;

static char data_lock_name[L_tmpnam];
static apr_global_mutex_t *data_lock = NULL;

static const char *userdata_key = "ntraffic_init_user_key";
static const char *shmdata_key = "ntraffic_init_shm_key";

typedef struct {
    apr_ipsubnet_t *ips;
} iplist;

/****************************************************************************    
    UTIL FUNCTIONS
 ***************************************************************************/

static apr_status_t add_vhost(const char *name, traffic_data_t ** vdata) {
    traffic_data_t *data;
    traffic_data_t *p;

    *vdata = NULL;
    data = (traffic_data_t *) shm_pool_alloc(main_shmp, sizeof(traffic_data_t));
    if (data) {
        memset(data, 0, sizeof(traffic_data_t));
        data->last_updated = apr_time_now();
        data->name = (char *) shm_pool_alloc(main_shmp, strlen(name) + 1);
        if (data->name) {
            strncpy(data->name, name, strlen(name) + 1);
        }

        apr_global_mutex_lock(data_lock);
        p = data_root;
        if (p == NULL) {
            data_root = data;
        } else {
            while (p->next) {
                p = p->next;
            }
            p->next = data;
        }
        apr_global_mutex_unlock(data_lock);
        *vdata = data;
        return APR_SUCCESS;
    }
    return DECLINED;
}

static traffic_data_t *search_vhost(const char *name) {
    traffic_data_t *this;
    this = (traffic_data_t *) shm_get_base(main_shmp);
    while (this != NULL) {
        if (!strncmp(name, this->name, strlen(name))) {
            return this;
        }
        this = this->next;
    }
    return NULL;
}

static void update_data(traffic_data_t * data, apr_uint32_t hits, apr_uint32_t sent, apr_uint32_t recvd) {
    if (data != NULL) {
        /* Using atomic functions we can avoid locks */

        /* The hits counter */
        apr_atomic_add32(&data->hits, hits);
        /* The traffic counters */
        apr_atomic_add32(&data->sent, sent);
        apr_atomic_add32(&data->recvd, recvd);
    }
}

static void flush_data(traffic_data_t * data) {
    if (data) {
        apr_atomic_set32(&data->hits, 0);
        apr_atomic_set32(&data->sent, 0);
        apr_atomic_set32(&data->recvd, 0);
    }
}

#if DEBUG
static void dump_vhost(traffic_data_t * data) {
    ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL,
                 MODULE_NAME " data for %s: hits: %lu sent: %lu received: %lu",
                 data->name,
                 (long unsigned int) data->hits, (long unsigned int) data->sent, (long unsigned int) data->recvd);
}
#endif

/****************************************************************************    
    LOGGING FUNCTIONS
 ***************************************************************************/

static void save_vhost_file(apr_pool_t * pool, const char *path, traffic_data_t * data, int dodel) {
    apr_file_t *f;
    apr_size_t len;
    apr_status_t rv;

    char buf[512];

    /* Remove the file to prevent possible security risks. open it to check that it exists */
    if (dodel != 0)
        if ((apr_file_open(&f, path, APR_READ | APR_BINARY, APR_OS_DEFAULT, pool)) == APR_SUCCESS) {
            apr_file_close(f);
            if ((apr_file_remove(path, pool)) != APR_SUCCESS) {
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL,
                             MODULE_NAME " Cannot delete file %s. Check permissions otherwise we won't be able to log.",
                             path);
                return;
            }
        }

    if ((rv =
         apr_file_open(&f, path, APR_READ | APR_WRITE | APR_CREATE | APR_BINARY, APR_OS_DEFAULT,
                       pool)) == APR_SUCCESS) {
        apr_file_lock(f, APR_FLOCK_EXCLUSIVE);
        snprintf(buf, sizeof(buf) - 1, "%lu %lu %lu\n",
                 (long unsigned int) data->sent, (long unsigned int) data->recvd, (long unsigned int) data->hits);
        len = strlen(buf);
        apr_file_write(f, buf, &len);
        apr_file_unlock(f);
        apr_file_close(f);
    } else {
        apr_strerror(rv, buf, sizeof buf);
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, MODULE_NAME " cannot fopen log file: %s", buf);
    }
}

static void save_vhost_accounting(apr_pool_t * pool, const char *basedir, apr_uint32_t interval, traffic_data_t * data) {
    char path[2048] = "";
    apr_time_t now, then, diff;

    if ((basedir == NULL) || (strlen(basedir) == 0)) {
        return;
    }

    /* 
       We should use locks. But removing the file, first, makes us reasonably sure that
       we are the only child writing there.
     */
    now = apr_time_now();
    then = data->last_updated;
    diff = now - then;

    if (diff > interval * 1000000) {
        data->last_updated = now;
    } else {
#ifdef DEBUG
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL,
                     "NOT Saving %s: interval = %lu  - diff = %lu ", data->name, (long unsigned int) interval,
                     (long unsigned int) diff / 1000000);
#endif

        return;
    }

#ifdef DEBUG
    ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL,
                 " YES Saving %s: interval = %lu  - diff = %lu ", data->name, (long unsigned int) interval,
                 (long unsigned int) diff / 1000000);
#endif
    snprintf(path, sizeof(path), "%s/%s.data", basedir, data->name);
    save_vhost_file(pool, path, data, 1);
}

static void load_vhost_file(apr_pool_t * pool, const char *path, traffic_data_t * data) {
    char buf[512];
    apr_file_t *f;
    apr_size_t len;

    char *s = NULL;
    char *r = NULL;
    char *h = NULL;
    char *foo = NULL;

    if ((apr_file_open(&f, path, APR_READ | APR_BINARY, APR_OS_DEFAULT, pool)) == APR_SUCCESS) {
        len = sizeof(buf) - 1;
        memset(buf, 0, sizeof(buf));
        if ((apr_file_read(f, buf, &len)) == APR_SUCCESS) {
            s = buf;
            if ((r = strchr(s, ' '))) {
                *r++ = '\0';
                if ((h = strchr(r, ' '))) {
                    *h++ = '\0';
                    if ((foo = strchr(h, '\n'))) {
                        *foo = '\0';
                    }
                }
            }
        }
        apr_file_close(f);
    }

    if (s && r && h) {
        apr_uint32_t vh = apr_atoi64(h);
        apr_uint32_t vs = apr_atoi64(s);
        apr_uint32_t vr = apr_atoi64(r);
        update_data(data, vh, vs, vr);
    }
}

static void load_vhost_accounting(apr_pool_t * pool, char *basedir, traffic_data_t * data) {
    char path[2048] = "";

    if ((basedir == NULL) || (strlen(basedir) == 0)) {
        return;
    }

    if (pool && data) {
        snprintf(path, sizeof(path), "%s/%s.data", basedir, data->name);
        load_vhost_file(pool, path, data);
    }
}

/****************************************************************************    
    ACCOUNTING FUNCTIONS
 ***************************************************************************/

/*  hook function pass to ap_table_do() */
static uint32_t GetHeaderLen(uint32_t * count, const char *key, const char *val) {
    int len = strlen(key) + strlen(val) + 4;    // 4 for ": " + CR + LF
    *count += len;
    return 1;
}

/*  computes the length of a table */
static uint32_t TableLen(request_rec * r, apr_table_t * tab) {
    uint32_t count = 0;

    if (tab) {
        apr_table_do((int (*)(void *, const char *, const char *)) GetHeaderLen, (void *) &count, tab, NULL);
    }

    return count;
}

static uint32_t BytesSent(request_rec * r) {
    uint32_t sent = 0;
    char *custom_response;
    apr_time_t reqtime;
    uint32_t status_len = 0;
    uint32_t serverver_len = 0;
    uint32_t date_len = 0;
    char datestring[APR_RFC822_DATE_LEN];

    // let's see if it's a failed redirect
    // I'm using the same logic of ap_send_error_response()
    custom_response = (char *) ap_response_code_string(r, ap_index_of_response(r->status));

    if (custom_response) {
        // if so, find the original request_rec
        if ((custom_response[0] != '"'))
            while (r->prev && (r->prev->status != HTTP_OK))
                r = r->prev;
    }

    if (r->status_line) {
        status_len = strlen(r->status_line) + strlen("HTTP/1.x ") + 2;
    }

    reqtime = r->request_time;
    apr_rfc822_date(datestring, reqtime);
    date_len = strlen(datestring) + strlen("Date: ") + 2;
    serverver_len = strlen(ap_get_server_banner()) + strlen("Server: ") + 2;

    sent = TableLen(r, r->headers_out) + TableLen(r, r->err_headers_out) + status_len + serverver_len + date_len + 2;   // 2 for CRLF

    if ((sent >= 255) && (sent <= 257)) {
        sent += sizeof("X-Pad: avoid browser bug") + 1;
    }

    if (r->sent_bodyct && r->bytes_sent) {
        sent += r->bytes_sent;
    }

    return sent;
}

static uint32_t BytesReceived(request_rec * r) {
    uint32_t recvd = 0;
    const char *clen;

    recvd = strlen(r->the_request) +    // The request
        TableLen(r, r->headers_in) +    // The headers
        2 +                     // 2 for CRLF after the request
        2;                      // 2 for CRLF after all headers

    clen = apr_table_get(r->headers_in, "Content-Length");

    if (clen) {
        recvd += strlen(clen);
    }
    return recvd;
}

/****************************************************************************    
    MAIN FUNCTION HOOK
 ***************************************************************************/

static int checkexclude(request_rec * r, apr_array_header_t * a) {
    int i;
    iplist *ips;

    ips = (iplist *) a->elts;

    for (i = 0; i < a->nelts; ++i) {

#if AP_SERVER_MINORVERSION_NUMBER == 2
        if (apr_ipsubnet_test(ips[i].ips, r->connection->remote_addr)) {
#elif AP_SERVER_MINORVERSION_NUMBER == 4
        if (apr_ipsubnet_test(ips[i].ips, r->connection->client_addr)) {
#endif
            return 1;
        }
    }
    return 0;
}

/* Process the log connection */
static int ntraffic_log_connection(request_rec * c) {
#if DEBUG
    const char *remote_peer;
#endif
    char *server_name;
    ntraffic_config_t *conf = NULL;
    traffic_data_t *data;
    uint32_t recvd = 0;
    uint32_t sent = 0;
    char *uri;

    /* If it's our handler, then don't update the stats */
    uri = apr_pstrdup(c->pool, c->uri);
    if (*uri == '/') {
        uri++;
    }

    if (!strcmp(uri, "ntraffic-status")) {
        return DECLINED;
    }

    /* Grab our config */
    conf = ap_get_module_config(c->server->module_config, &ntraffic_module);
    if (conf == NULL) {
        return DECLINED;
    }

    if (!conf->enabled) {
        return OK;
    }

    /* lookup the remote peer */
    if (checkexclude(c, conf->exclude)) {
#if DEBUG
        remote_peer = c->connection->remote_ip;
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, MODULE_NAME " Excluding ip %s", remote_peer);
#endif
        return OK;
    }

    /* Grab our traffic data */
    sent = BytesSent(c);
    recvd = BytesReceived(c);

    /* SERVER TOTALS */
    data = search_vhost(TOTALS_NAME);
    if (data != NULL) {
        update_data(data, 1, sent, recvd);
        save_vhost_accounting(c->pool, conf->data_dir, conf->update_interval, data);
#ifdef DEBUG
        dump_vhost(data);
#endif
    }

    /* THIS VHOST */
    /* extract server name */
    server_name = conf->name;
    if (server_name == NULL) {
        server_name = c->server->server_hostname;
    }

    if (server_name == NULL) {
#if DEBUG
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, c->server, MODULE_NAME " Not accounting request for '%s'.", server_name);
#endif
        return OK;
    }

    data = search_vhost(server_name);
    if (!data) {
#ifdef DEBUG
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, c->server,
                     MODULE_NAME " creating traffic data for vhost %s", server_name);
#endif
        add_vhost(server_name, &data);
        load_vhost_accounting(c->pool, conf->data_dir, data);
    }

    if (data) {
        update_data(data, 1, sent, recvd);
        save_vhost_accounting(c->pool, conf->data_dir, conf->update_interval, data);
#ifdef DEBUG
        dump_vhost(data);
#endif
    }

    return OK;
}

static void ntraffic_child_init(apr_pool_t * p, server_rec * s) {
    void *data;
#ifdef DEBUG
    ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, MODULE_NAME " Child Init");
#endif

    ntraffic_config_t *conf;
    /* Grab our config */
    conf = ap_get_module_config(s->module_config, &ntraffic_module);

    /* Don't initialize anything if we shouldn't */
    if (!conf || !conf->enabled)
        return;

    apr_pool_userdata_get(&data, shmdata_key, s->process->pool);
    main_shmp = data;

    apr_global_mutex_child_init(&data_lock, data_lock_name, p);
}

/****************************************************************************    
    MAIN FUNCTION HANDLER
 ***************************************************************************/

static int ntraffic_handler(request_rec * r) {
    char buf[512];
    char *server_name;
    traffic_data_t *this;
    ntraffic_config_t *conf;
    int globals = 0;
    int plain = 0;
    int json = 0;
    int flush = 0;

    // TODO IF module is disabled, return

    if (strcmp(r->handler, NTRAFFIC_MAGIC_TYPE) && strcmp(r->handler, "ntraffic-status")) {
        return DECLINED;
    }

    if (!ap_exists_scoreboard_image()) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Server status unavailable in inetd mode");
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Grab our config */
    conf = ap_get_module_config(r->server->module_config, &ntraffic_module);

    /* server_name = (char *) ap_get_server_name(r); */
    server_name = conf->name;
    if (server_name == NULL) {
        server_name = r->server->server_hostname;
    }

    if (server_name == NULL) {
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Parse our arguments */
    if (r->args) {
        if ((strcasestr(r->args, "globals") != NULL)) {
            globals = 1;
        }
        if ((strcasestr(r->args, "plain") != NULL)) {
            plain = 1;
        }
        if ((strcasestr(r->args, "json") != NULL)) {
            json = 1;
        }
        if ((strcasestr(r->args, "flush") != NULL)) {
            flush = 1;
        }
    }

    /* And finally prepare the output */

    if (plain) {
        ap_set_content_type(r, "text/plain; charset=ISO-8859-1");
    } else if (json) {
        ap_set_content_type(r, "application/json; charset=ISO-8859-1");
        ap_rputs("[\n", r);
    } else {
        ap_set_content_type(r, "text/xml; charset=UTF-8");
        ap_rputs("<document type=\"ntraffic/xml\">\n", r);
        ap_rputs("<ntraffic-data>\n", r);
    }

    if (globals) {
        this = search_vhost(server_name);
        if (!this) {
            add_vhost(server_name, &this);
            load_vhost_accounting(r->pool, conf->data_dir, this);
        }

        this = (traffic_data_t *) shm_get_base(main_shmp);

        while (this) {
            if (plain) {
                snprintf(buf, sizeof(buf) - 1,
                         "%lu\t%lu\t%lu\t%s\n",
                         (long unsigned int) this->hits,
                         (long unsigned int) this->sent, (long unsigned int) this->recvd, this->name);
            } else if (json) {
                snprintf(buf, sizeof(buf) - 1,
                         " { \n"
                         "  \"hits\": %lu, \n"
                         "  \"sent\": %lu, \n"
                         "  \"recvd\": %lu, \n"
                         "  \"name\": \"%s\" \n"
                         " }%s",
                         (long unsigned int) this->hits,
                         (long unsigned int) this->sent, (long unsigned int) this->recvd, this->name,
                         (this->next == NULL) ? "\n" : ",\n");
            } else {
                snprintf(buf, sizeof(buf) - 1,
                         "<vhost name=\"%s\" hits=\"%lu\" sent=\"%lu\" recvd=\"%lu\" />\n",
                         this->name,
                         (long unsigned int) this->hits,
                         (long unsigned int) this->sent, (long unsigned int) this->recvd);
            }
            ap_rputs(buf, r);
            if (flush) {
                flush_data(this);
            }
            this = this->next;
        }
    } else {
        this = search_vhost(server_name);
        if (!this) {
            add_vhost(server_name, &this);
            load_vhost_accounting(r->pool, conf->data_dir, this);
        }
        if (this) {
            if (plain) {
                snprintf(buf, sizeof(buf) - 1,
                         "%lu\t%lu\t%lu\t%s\n",
                         (long unsigned int) this->hits,
                         (long unsigned int) this->sent, (long unsigned int) this->recvd, this->name);
            } else if (json) {
                snprintf(buf, sizeof(buf) - 1,
                         " { \n"
                         "  \"hits\": %lu, \n"
                         "  \"sent\": %lu, \n"
                         "  \"recvd\": %lu, \n"
                         "  \"name\": \"%s\" \n"
                         " }",
                         (long unsigned int) this->hits,
                         (long unsigned int) this->sent, (long unsigned int) this->recvd, this->name);
            } else {
                snprintf(buf, sizeof(buf) - 1,
                         "<vhost name=\"%s\" hits=\"%lu\" sent=\"%lu\" recvd=\"%lu\" />\n",
                         this->name,
                         (long unsigned int) this->hits,
                         (long unsigned int) this->sent, (long unsigned int) this->recvd);
            }
            ap_rputs(buf, r);
            if (flush) {
                flush_data(this);
            }
        }
    }

    if (plain) {
    } else if (json) {
        ap_rputs("]", r);
    } else {
        ap_rputs("</ntraffic-data>", r);
        ap_rputs("</document>", r);
    }

    return 0;

}

/****************************************************************************    
    CONFIG FUNCTIONS
 ***************************************************************************/

/* Process the enable directive */
static const char *ntraffic_config_enabled(cmd_parms * cmd, void *dummy, int arg) {
    ntraffic_config_t *conf;
    const char *errmsg;

    errmsg = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (errmsg != NULL) {
        return errmsg;
    }

    conf = ap_get_module_config(cmd->server->module_config, &ntraffic_module);
    if (conf) {
        conf->enabled = arg;
    }
    return NULL;
}

static const char *ntraffic_config_updint(cmd_parms * cmd, void *dummy, const char *arg) {
    ntraffic_config_t *conf;
    int interval = 120;
    const char *errmsg;

    errmsg = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (errmsg != NULL) {
        return errmsg;
    }

    conf = ap_get_module_config(cmd->server->module_config, &ntraffic_module);
    if (conf) {
        interval = atoi(arg);
        if ((interval > 43200) || (interval < 10)) {
            conf->update_interval = 120;
            return "NTrafficRefreshInterval must be between 10 and 43200 (12 hours).";
        } else {
            conf->update_interval = interval;
        }
    }
    return NULL;
}

static const char *ntraffic_config_datadir(cmd_parms * cmd, void *dummy, const char *arg) {
    ntraffic_config_t *conf;
    const char *errmsg;

    errmsg = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (errmsg != NULL) {
        return errmsg;
    }

    conf = ap_get_module_config(cmd->server->module_config, &ntraffic_module);
    if (conf) {
        conf->data_dir = apr_pstrdup(cmd->pool, arg);
    }
    return NULL;
}

static const char *ntraffic_config_servername(cmd_parms * cmd, void *dummy, const char *arg) {
    ntraffic_config_t *conf;
    const char *errmsg;

    errmsg = ap_check_cmd_context(cmd, NOT_IN_VIRTUALHOST);
    if (errmsg == NULL) {
        /* We want to be inside a virtual host */
        return NULL;
    }

    conf = ap_get_module_config(cmd->server->module_config, &ntraffic_module);
    if (conf != NULL) {
#ifdef DEBUG
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, MODULE_NAME " Server config set for '%s'", arg);
#endif
        conf->name = apr_pstrdup(cmd->pool, arg);;
        conf->vh = 1;
    }

    return NULL;
}

/* Parse the NoIPLimit directive */
static const char *ntraffic_config_exclip(cmd_parms * cmd, void *dummy, const char *arg) {
    ntraffic_config_t *conf;
    apr_status_t rv;
    char *s;
    char msgbuf[120];
    iplist *subnet;
    const char *errmsg;
    char *ip;

    errmsg = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (errmsg != NULL) {
        return errmsg;
    }

    conf = ap_get_module_config(cmd->server->module_config, &ntraffic_module);

    ip = apr_pstrdup(cmd->pool, arg);
    subnet = (iplist *) apr_array_push(conf->exclude);

    if ((s = ap_strchr(ip, '/'))) {
        *s++ = '\0';
        rv = apr_ipsubnet_create(&subnet->ips, ip, s, cmd->pool);
        if (APR_STATUS_IS_EINVAL(rv)) {
            /* looked nothing like an IP address */
            return "An IP address was expected";
        } else if (rv != APR_SUCCESS) {
            apr_strerror(rv, msgbuf, sizeof msgbuf);
            return apr_pstrdup(cmd->pool, msgbuf);
        }
#if DEBUG
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, MODULE_NAME " EXCLUDE NETMASK %s/%s", ip, s);
#endif
    } else if (!APR_STATUS_IS_EINVAL(rv = apr_ipsubnet_create(&subnet->ips, ip, NULL, cmd->pool))) {
        if (rv != APR_SUCCESS) {
            apr_strerror(rv, msgbuf, sizeof msgbuf);
            return apr_pstrdup(cmd->pool, msgbuf);
        }
#if DEBUG
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, MODULE_NAME " EXCLUDE IP %s", ip);
#endif
    } else {
        apr_snprintf(msgbuf, sizeof(msgbuf), "IP/Subnet not valid");
        return apr_pstrdup(cmd->pool, msgbuf);
    }

    return NULL;
}

static apr_status_t cleanup_mutex(void *foo) {
#ifdef DEBUG
    ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, MODULE_NAME " Cleaning up mutex");
#endif

    if (data_lock) {
        apr_global_mutex_destroy(data_lock);
        data_lock = NULL;
    }
    return APR_SUCCESS;
}

static void *ntraffic_server_merge(apr_pool_t * p, void *base_conf, void *new_conf) {
    ntraffic_config_t *server = base_conf;
    ntraffic_config_t *vh = new_conf;
#ifdef DEBUG
    if (vh->vh) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, MODULE_NAME " Merging conf for VH %s", vh->name);
    } else {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, MODULE_NAME " SKIPPING merging main conf");
    }
#endif

    if (vh->vh) {
        vh->enabled = server->enabled;
        vh->update_interval = server->update_interval;
        vh->data_dir = server->data_dir;
        vh->exclude = server->exclude;
    }

    return new_conf;
}

/* Create per-server configuration */
static void *ntraffic_server_config(apr_pool_t * p, server_rec * s) {
    ntraffic_config_t *conf;

#ifdef DEBUG
    ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, MODULE_NAME " Server config");
#endif

    conf = apr_pcalloc(p, sizeof(ntraffic_config_t));
    if (conf) {
        conf->name = NULL;
        conf->vh = 0;
        conf->enabled = 0;
        conf->update_interval = DEFAULT_UPDATE_INTERVAL;
        conf->data_dir = NULL;
        conf->exclude = apr_array_make(p, 0, sizeof(iplist));
    }

    return conf;
}

static apr_status_t cleanup_shmem(void *foo) {
#ifdef DEBUG
    ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, MODULE_NAME " Cleaning up shmem");
#endif

    if (main_shmp) {
        shm_pool_destroy(main_shmp);
        main_shmp = NULL;
    }
    return APR_SUCCESS;
}

static apr_status_t cleanup_and_save_data(void *data) {
    server_rec *s = (server_rec *) data;
    ntraffic_config_t *conf;
    char path[2048];
    traffic_data_t *this;

#ifdef DEBUG
    ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, " Cleaning up and saving data");
#endif

    conf = ap_get_module_config(s->module_config, &ntraffic_module);
    if (!conf) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, " Cannot get configuration data");
        return !OK;
    }

    /* If we are not enabled, don't even try to save anyhing. */
    if (!conf->enabled) {
        return OK;
    }

    /* If we have no datadir, skip all */
    if ((conf->data_dir == NULL) || (strlen(conf->data_dir) == 0)) {
        return OK;
    }

    /* Now save */
    this = (traffic_data_t *) shm_get_base(main_shmp);
    while (this) {
        snprintf(path, sizeof(path), "%s/%s.data", conf->data_dir, this->name);
#ifdef DEBUG
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, MODULE_NAME " Cleaning up and saving data: %s", path);
#endif
        save_vhost_file(s->process->pool, path, this, 0);
        this = this->next;
    }

    return APR_SUCCESS;
}

/* Set up startup-time initialization */
static int ntraffic_init(apr_pool_t * p, apr_pool_t * plog, apr_pool_t * ptemp, server_rec * s) {
    void *data;
    apr_status_t status;
    apr_size_t shm_size;
    shm_pool_t *shmp;
    traffic_data_t *totals;
    ntraffic_config_t *conf;
    apr_pool_t *newpool;
    char *tmpfile;

    /* Init APR's atomic functions */
    status = apr_atomic_init(p);
    if (status != APR_SUCCESS) {
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    ap_add_version_component(p, MODULE_COMPONENT_STR);

    conf = ap_get_module_config(s->module_config, &ntraffic_module);

    /*
     * ntraffic_init() will be called twice, and if it's a DSO
     * then all static data from the first call will be lost. Only
     * set up our static data on the second call.
     *
     */
    apr_pool_userdata_get(&data, userdata_key, s->process->pool);
    if (!data) {
#ifdef DEBUG
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, MODULE_NAME " Not Initializing ...");
#endif
        apr_pool_userdata_set((const void *) 1, userdata_key, apr_pool_cleanup_null, s->process->pool);

        return OK;
    }
#ifdef DEBUG
    ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, MODULE_NAME " Initializing module");
#endif

    /* If we are not enabled, don't even try to save anyhing. */
    if (!conf->enabled) {
        return OK;
    }

    /* The global mutex stuff */
    tmpfile = tmpnam(data_lock_name);
    (void) tmpfile; /* shutup picky compilers */

    status = apr_global_mutex_create(&data_lock, data_lock_name, APR_LOCK_DEFAULT, p);
    if (status != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, status, s, MODULE_NAME " Cannot initialize data lock");
        return status;
    }
    //apr_pool_cleanup_register(p, data_lock, (void*)apr_global_mutex_destroy, apr_pool_cleanup_null) ;
    apr_pool_cleanup_register(p, data_lock, cleanup_mutex, apr_pool_cleanup_null);

#ifdef AP_NEED_SET_MUTEX_PERMS

#if AP_SERVER_MINORVERSION_NUMBER == 2
    status = unixd_set_global_mutex_perms(data_lock);
#elif AP_SERVER_MINORVERSION_NUMBER == 4
    status = ap_unixd_set_global_mutex_perms(data_lock);
#endif
    if (status != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, status, s,
                     "Parent could not set permissions on global mutex:" " check User and Group directives");
        return status;
    }
#endif

    /* The SHM stuff */
    apr_pool_userdata_get(&data, shmdata_key, s->process->pool);
    if (data) {
#ifdef DEBUG
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, MODULE_NAME " SHM EXISTS");
#endif
        main_shmp = shmp = data;
        data_root = (traffic_data_t *) shm_get_base(main_shmp);
    } else {
#ifdef DEBUG
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, MODULE_NAME " Initializing ...");
#endif
        /* 
           At first, we create a subpool of the process pool.
           This is needed to workaround a bug that prevents the process pool
           to process it's cleanup hooks
         */
        status = apr_pool_create(&newpool, s->process->pool);
        if (status != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, MODULE_NAME " Cannot initialize subpool for shmp");
            return !OK;
        }
        // Initialize our shared memory pool
        shm_size = (apr_size_t) sizeof(traffic_data_t) * MAX_VHOSTS;
        status = shm_pool_create(newpool, shm_size, &shmp);

        if (status != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, MODULE_NAME " Cannot initialize shared memory pool");
            return !OK;
        }
        apr_pool_cleanup_register(newpool, NULL, cleanup_shmem, apr_pool_cleanup_null);
        apr_pool_cleanup_register(newpool, s, cleanup_and_save_data, apr_pool_cleanup_null);

        main_shmp = shmp;

        add_vhost(TOTALS_NAME, &totals);
        load_vhost_accounting(p, conf->data_dir, totals);
#if DEBUG
        shm_dump(main_shmp);
#endif
        apr_pool_userdata_set(shmp, shmdata_key, apr_pool_cleanup_null, s->process->pool);

    }

    return OK;
}

/****************************************************************************    
    MODULE HOOKS AND DEFINITIONS
 ***************************************************************************/

/* Array describing structure of configuration directives */
static command_rec ntraffic_cmds[] = {
    AP_INIT_FLAG("NTrafficEnabled", ntraffic_config_enabled, NULL, RSRC_CONF, "Enable NTraffic module"),

    AP_INIT_TAKE1("NTrafficRefreshInterval", ntraffic_config_updint, NULL, RSRC_CONF,
                  "Update interval of the stats file (in seconds)"),
    AP_INIT_TAKE1("NTrafficDataDir", ntraffic_config_datadir, NULL, RSRC_CONF,
                  "The directory used to store our data"),

    AP_INIT_ITERATE("NTrafficExcludeIP", ntraffic_config_exclip, NULL, RSRC_CONF,
                    "Ip or Netmask to exclude from our traffic logs"),

    AP_INIT_TAKE1("ServerName", ntraffic_config_servername, NULL, RSRC_CONF,
                  "Grabs the ServerName from the Virtual host."),

    {NULL},
};

static void register_hooks(apr_pool_t * pool) {
    ap_hook_child_init(ntraffic_child_init, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_post_config(ntraffic_init, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_log_transaction(ntraffic_log_connection, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_handler(ntraffic_handler, NULL, NULL, APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA ntraffic_module = {
    STANDARD20_MODULE_STUFF,
    NULL,                       /* create per-dir config structures */
    NULL,                       /* merge  per-dir    config structures */
    ntraffic_server_config,     /* create per-server config structures */
    ntraffic_server_merge,      /* merge  per-server config structures */
    ntraffic_cmds,              /* table of config file commands       */
    register_hooks              /* handlers registration */
};
