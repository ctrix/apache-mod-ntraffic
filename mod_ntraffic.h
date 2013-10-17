
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
#include "ap_mpm.h"
#include "apr_strings.h"
#include "apr_atomic.h"
#include "scoreboard.h"

/* Uncomment to be flooded with error messages (to debug, obviously */
//#define DEBUG             1

#define MODULE_NAME		"mod_ntraffic"
#define MODULE_VERSION 		"0.5"
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
