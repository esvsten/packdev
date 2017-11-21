#ifndef PACKDEV_CRYPTO_H_
#define PACKDEV_CRYPTO_H_

#include <rte_mempool.h>
#include <rte_common.h>

typedef struct {
    uint8_t id;
    uint16_t qp_id;
    struct rte_mempool *operation_pool;
} packdev_crypto_dev_t;

void packdev_crypto_init();

packdev_crypto_dev_t* packdev_crypto_get_device();

#endif /* PACKDEV_CRYPTO_H_ */
