#ifndef PACKDEV_PORT_H_
#define PACKDEV_PORT_H_

#include "packdev_common.h"

struct mbuf_table {
    uint16_t len;
    struct rte_mbuf *m_table[DEFAULT_PKT_BURST];
};

typedef struct tx_queue_info_s {
    struct mbuf_table tx_mbufs;
} tx_queue_info_t;

typedef struct rx_queue_info_s {
    struct rte_mempool *mempool;
} rx_queue_info_t;

typedef struct packdev_port_s {
    uint16_t port_id;
    uint16_t tx_burst;

    uint16_t num_rx_queues;
    uint16_t num_rx_mbufs;

    rx_queue_info_t rx_queue[NUM_RX_QUEUES_PER_PORT];
    tx_queue_info_t tx_queue[NUM_TX_QUEUES_PER_PORT];

    uint16_t num_tx_queues;
} packdev_port_t;



void packdev_port_init();

void packdev_port_destroy();

packdev_port_t* packdev_port_get(uint32_t port_id);

struct rte_mempool* packdev_port_get_tx_mp();

void packdev_port_mac_addr_print(uint32_t port_id);

#endif // PACKDEV_PORT_H_
