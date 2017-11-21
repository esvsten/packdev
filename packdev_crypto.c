
/* Fast Path packet processing prototype

   see also: ip_fastpath.h

   sven.s.stenstrom@ericsson.com

 */

#include <sys/types.h>
#include <unistd.h>
#include <stdbool.h>
#include <assert.h>

#include <rte_eal.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_vdev.h>
#include <rte_crypto.h>
#include <rte_crypto_sym.h>
#include <rte_cryptodev.h>
#include <rte_common.h>

#include "packdev_common.h"
#include "packdev_crypto.h"

packdev_crypto_dev_t global_crypto_dev;

void packdev_crypto_init() {
    uint8_t socket_id = rte_socket_id();

    /* Create the virtual crypto device. */
    const char *crypto_name = RTE_STR(CRYPTODEV_NAME_OPENSSL_PMD)"0";
    char crypto_vdev_args[128];
    snprintf(crypto_vdev_args,
            sizeof(crypto_vdev_args),
            "socket_id=%d", socket_id);
    if (rte_vdev_init(crypto_name, crypto_vdev_args) != 0) {
        rte_exit(EXIT_FAILURE, "CRYPTO: Cannot create crypto device");
    }

    global_crypto_dev.id = rte_cryptodev_get_dev_id(crypto_name);

    /*
     * The IV is always placed after the crypto operation,
     * so some private data is required to be reserved.
     */
    uint32_t crypto_op_private_data = MAX_IV_LENGTH;

    /* Create crypto operation pool. */
    global_crypto_dev.operation_pool = rte_crypto_op_pool_create(
            "operation_pool",
            RTE_CRYPTO_OP_TYPE_SYMMETRIC,
            MAX_NUM_CRYPTO_MBUFS,
            CRYPTO_CACHE_SIZE,
            crypto_op_private_data,
            socket_id);
    if (global_crypto_dev.operation_pool == NULL) {
        rte_exit(EXIT_FAILURE, "CRYPTO: Cannot create operations op pool\n");
    }

    /* Configure the crypto device. */
    struct rte_cryptodev_config cryptodev_config = {
        .nb_queue_pairs = 1,
        .socket_id = socket_id,
        .session_mp = {
            .nb_objs = MAX_NUM_CRYPTO_SESSIONS * 2,
            .cache_size = CRYPTO_CACHE_SIZE,
        },
    };

    struct rte_cryptodev_qp_conf queue_pair_config = {
        .nb_descriptors = MAX_NUM_CRYPTO_SESSIONS * 2,
    };

    if (rte_cryptodev_configure(global_crypto_dev.id, &cryptodev_config) < 0) {
        rte_exit(EXIT_FAILURE,
                "CRYPTO: Failed to configure cryptodev %u", global_crypto_dev.id);
    }

    global_crypto_dev.qp_id = 0;
    if (rte_cryptodev_queue_pair_setup(
                global_crypto_dev.id,
                global_crypto_dev.qp_id,
                &queue_pair_config,
                socket_id) < 0) {
        rte_exit(EXIT_FAILURE, "CRYPTO: Failed to setup queue pair\n");
    }

    if (rte_cryptodev_start(global_crypto_dev.id) < 0) {
        rte_exit(EXIT_FAILURE, "CRYPTO: Failed to start device\n");
    }
}

packdev_crypto_dev_t* packdev_crypto_get_device() {
    return &global_crypto_dev;
}
