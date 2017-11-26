
/* Fast Path packet processing prototype

   see also: ip_fastpath.h

   sven.s.stenstrom@ericsson.com

 */

#include <sys/types.h>
#include <unistd.h>
#include <stdint.h>

#include <rte_cycles.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_log.h>

#include "packdev_common.h"
#include "packdev_eth.h"
#include "packdev_port.h"

static packdev_port_t port_data[MAX_NUM_OF_PORTS];
static struct rte_mempool* tx_mp = NULL;

static inline int port_init(uint8_t port_id)
{
    int retval;

    const struct rte_eth_conf port_conf = {
        .rxmode = {
            .max_rx_pkt_len = ETHER_MAX_LEN,
            .mq_mode = ETH_MQ_RX_RSS
        },
        .rx_adv_conf = {
            .rss_conf = {
            .rss_hf = ETH_RSS_IP | ETH_RSS_UDP | ETH_RSS_TCP,
            }
        },
    };

    if (port_id >= rte_eth_dev_count()) {
        return -1;
    }

    packdev_port_t *port = &port_data[port_id];
    port->port_id = port_id;
    port->tx_burst = DEFAULT_PKT_BURST;
    port->num_rx_mbufs = MAX_RX_MBUFS_PER_PORT;
    port->num_rx_queues = NUM_RX_QUEUES_PER_PORT;
    port->num_tx_queues = NUM_TX_QUEUES_PER_PORT;

    /* configure ethernet device. */
    retval = rte_eth_dev_configure(
            port_id,
            port->num_rx_queues,
            port->num_tx_queues,
            &port_conf);
    if (retval != 0) {
        return retval;
    }

    /* allocate and set up RX queues for each port */
    for (uint16_t queue_id = 0; queue_id < port->num_rx_queues; queue_id++) {
        /* initalize memory packet buffers */
        char rx_queue_mempool_name[RTE_MEMZONE_NAMESIZE];
        snprintf(rx_queue_mempool_name, sizeof(rx_queue_mempool_name),
                "rx_mp%u:%u", port_id, queue_id);
        port->rx_queue[queue_id].mempool = rte_pktmbuf_pool_create(
                rx_queue_mempool_name,
                port->num_rx_mbufs,
                MBUF_RX_CACHE_SIZE,
                DEFAULT_MBUF_PRIV_SIZE,
                RTE_MBUF_DEFAULT_BUF_SIZE,
                rte_socket_id());
        if (port->rx_queue[queue_id].mempool == NULL) {
            rte_exit(EXIT_FAILURE, "Cannot create rx mbuf pool\n");
        }

        /* set up receive queue */
        retval = rte_eth_rx_queue_setup(
                port_id,
                queue_id,
                DEFAULT_RX_DESC,
                rte_eth_dev_socket_id(port_id),
                NULL /* rte_eth_rxconf */,
                port->rx_queue[queue_id].mempool);
        if (retval < 0) {
            return retval;
        }
    }

    /* allocate and set up TX queues for each port. */
    for (uint16_t queue_id = 0; queue_id < port->num_tx_queues; queue_id++) {
        retval = rte_eth_tx_queue_setup(
                port_id,
                queue_id,
                DEFAULT_TX_DESC,
                rte_eth_dev_socket_id(port_id),
                NULL /* rte_eth_txconf */);
        if (retval < 0) {
            return retval;
        }
    }

    /* start port */
    if (rte_eth_dev_start(port_id)  < 0) {
        return retval;
    }

    /* print MAC address */
    packdev_port_mac_addr_print(port_id);

    /* set promiscious mode */
    rte_eth_promiscuous_enable(port_id);

    return 0;
}

void packdev_port_init()
{
    /* configure Ethernet device */
    uint32_t num_ports = rte_eth_dev_count();
    RTE_LOG(INFO, USER1, "Number of ports active: %u\n", num_ports);

    /* Initialize all ports. */
    RTE_LOG(INFO, USER1, "***Initializing all ports***\n");
    memset(&port_data, 0, sizeof(port_data));
    for (uint32_t port_id = 0; port_id < num_ports; port_id++) {
        if (port_init(port_id) != 0) {
            rte_exit(EXIT_FAILURE,
                    "Cannot init port %"PRIu8 "\n", port_id);
        }
    }

    /* initalize memory packet buffers */
    tx_mp = rte_pktmbuf_pool_create(
            "tx_mp",
            MAX_TX_MBUFS,
            MBUF_TX_CACHE_SIZE,
            DEFAULT_MBUF_PRIV_SIZE,
            RTE_MBUF_DEFAULT_BUF_SIZE,
            rte_socket_id());
    if (tx_mp == NULL) {
        rte_exit(EXIT_FAILURE, "Cannot create tx mbuf pool\n");
    }
}

void packdev_port_destroy() {
    uint32_t num_ports = rte_eth_dev_count();
    RTE_LOG(INFO, USER1, "Number of ports active: %u\n", num_ports);

    /* Stop all ports. */
    RTE_LOG(INFO, USER1, "***Destorying all ports***\n");
    for (uint32_t port_id = 0; port_id < num_ports; port_id++) {
        if (port_data[port_id].port_id != port_id) {
            rte_eth_dev_stop(port_id);
            rte_delay_ms(100);
            rte_eth_dev_close(port_id);
        }
    }
}

packdev_port_t* packdev_port_get(uint32_t port_id) {
    if (port_id < MAX_NUM_OF_PORTS &&
            port_data[port_id].port_id == port_id) {
        return &port_data[port_id];
    }

    return NULL;
}

struct rte_mempool* packdev_port_get_tx_mp() {
    return tx_mp;
}

void packdev_port_mac_addr_print(uint32_t port_id) {
    struct ether_addr addr;
    rte_eth_macaddr_get(port_id, &addr);

    RTE_LOG(DEBUG, USER1, "Port %u: \n", port_id);
    packdev_eth_print_addr(addr);
}
