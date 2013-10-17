
#include "mod_ntraffic.h"

struct shm_pool_data {
    void *data;
};

struct shm_pool {
    apr_shm_t *shm;
    size_t size;
    size_t used;
    void *mem;
};

/* ************************************************************************************** */

void shm_dump(shm_pool_t * spool) {
    ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, MODULE_NAME " SHM size: %ld  used: %ld", (long) spool->size,
                 (long) spool->used);
}

void *shm_get_base(shm_pool_t * spool) {
    return spool->mem;
}

apr_status_t shm_pool_create(apr_pool_t * pool, size_t shm_size, shm_pool_t ** shpool) {
    apr_status_t status;
    apr_shm_t *shm;
    apr_size_t sz;
    apr_size_t retsize;
    shm_pool_t *shmp;
    //shm_pool_data_t *shmpd;

    /* Create shared memory block */
    sz = sizeof(struct shm_pool) + sizeof(struct shm_pool_data) + shm_size;

    status = apr_shm_create(&shm, sz, tmpnam(NULL), pool);
    if (status != APR_SUCCESS) {
        return status;
    }

    /* Check size of shared memory block */
    retsize = apr_shm_size_get(shm);

    if (retsize != sz) {
        return status;
    }

    void *base = apr_shm_baseaddr_get(shm);
    if (base == NULL) {
        return status;
    }
    memset(base, 0, retsize);

    // Here i have the BASE ADDRESS and SHM to keep around the processes

    /* Init shm block */
    shmp = base;
    shmp->mem = shmp + sizeof(shm_pool_t);
    shmp->size = shm_size - sizeof(shm_pool_t);
    shmp->used = 0;
    shmp->shm = shm;
    //shmpd = shmp->mem;

    *shpool = shmp;

    return APR_SUCCESS;
}

void *shm_pool_alloc(shm_pool_t * sm, apr_size_t size) {
    void *mem = NULL;
    shm_pool_data_t *data;

    data = sm->mem;

    if (!sm || !data || size <= 0) {
        return NULL;
    }

    if (sm->size < sm->used + size) {
        return NULL;
    } else {
        mem = sm->mem + sm->used;
        sm->used += size;
    }

    return mem;
}

apr_status_t shm_pool_destroy(shm_pool_t * shm_pool) {
    /* If there was a memory block already assigned.. destroy it */
    apr_status_t status;

    if (shm_pool->shm) {
        status = apr_shm_destroy(shm_pool->shm);
        if (status != APR_SUCCESS) {
            return status;
        }
    }
    return APR_SUCCESS;
}
