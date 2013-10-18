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

#include <assert.h>

#include "httpd.h"
#include "http_config.h"
#include "http_request.h"
#include "http_protocol.h"
#include "http_core.h"
#include "http_main.h"
#include "http_log.h"
#include "unixd.h"

#include "mod_core.h"

#include "ap_release.h"
#include "ap_mpm.h"
#include "scoreboard.h"

#include "apr_strings.h"
#include "apr_atomic.h"

/* Uncomment to be flooded with error messages (to debug, obviously */
//#define DEBUG             1

#define MODULE_NAME		"mod_ntraffic"
#define MODULE_VERSION 		"0.6"
#define MODULE_COMPONENT_STR 	"mod_ntraffic/0.5"
#define DEFAULT_DATA_DIR 	"/www/var/spool/apache2/mod_traffic"
#define DEFAULT_UPDATE_INTERVAL 60
#define MAX_VHOSTS		8192
#define TOTALS_NAME		"__TOTALS__"
#define NTRAFFIC_MAGIC_TYPE 	"application/x-httpd-status"

/****************************************************************************    
    MAIN STRUCTURES
 ***************************************************************************/

typedef struct ntraffic_config_s ntraffic_config_t;
typedef struct traffic_data_s traffic_data_t;

typedef struct shm_pool_data shm_pool_data_t;
typedef struct shm_pool shm_pool_t;

struct ntraffic_config_s {
    char *name;
    short int vh;
    short int enabled;
    apr_uint32_t update_interval;
    char *data_dir;
    apr_array_header_t *exclude;
};

struct traffic_data_s {
    char *name;

    apr_uint32_t hits;
    apr_uint32_t recvd;
    apr_uint32_t sent;
    apr_time_t last_updated;

    traffic_data_t *next;
};

void shm_dump(shm_pool_t * spool);
void *shm_get_base(shm_pool_t * spool);
apr_status_t shm_pool_create(apr_pool_t * p, size_t shm_size, shm_pool_t ** shpool);
void *shm_pool_alloc(shm_pool_t * sm, apr_size_t size);
apr_status_t shm_pool_destroy(shm_pool_t * shm_pool);
