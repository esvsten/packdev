
/* Fast Path packet processing prototype

   see also: ip_fastpath.h

   sven.s.stenstrom@ericsson.com

 */

#include <sys/types.h>
#include <assert.h>

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_common.h>
#include <rte_mbuf.h>

#include <rte_ether.h>
#include <rte_debug.h>

#include "packdev_common.h"
#include "packdev_packet.h"
#include "packdev_port.h"
#include "packdev_eth.h"
#include "packdev_vlan.h"
#include "packdev_ipv4.h"

static void packdev_packet_classify(
        struct rte_mbuf *packet,
        uint16_t port_id) {
    packdev_port_t *port_data = packdev_port_get(port_id);
    assert(port_data != NULL);

    uint16_t ether_type = packdev_eth_get_type(packet);

    switch (ether_type) {
    case ETHER_TYPE_VLAN:
        /* Frees the mbuf */
        packdev_vlan_process(packet, port_id);
        break;
    case ETHER_TYPE_IPv4:
        /* Frees the mbuf */
        packdev_ipv4_process(packet, port_id, false /*inner packet (false) */);
        break;
    default:
        RTE_LOG(INFO, USER1, "Unknown ether type: %u\n", ether_type);
        RTE_LOG(INFO, USER1, "Do not know how to handle ether type: %u\n", ether_type);
        rte_pktmbuf_free(packet);
        break;
    }
}

static void packdev_packet_classify_bulk(
        struct rte_mbuf **pkts,
        uint16_t num_pkts,
        uint16_t port_id) {
    for (uint16_t i = 0 ; i < num_pkts; i++) {
        struct ether_hdr *eth_hdr = packdev_eth_get_hdr(pkts[i]);
        packdev_eth_print_addr(eth_hdr->s_addr);
        packdev_eth_print_addr(eth_hdr->d_addr);

        packdev_packet_classify(pkts[i], port_id);
    }
}

void packdev_packet_receive(
        uint8_t port_id,
        uint16_t queue_id,
        struct rte_mbuf *pkts[],
        uint16_t max_num_pkts) {
    uint16_t num_recv_pkts = rte_eth_rx_burst(
            port_id,
            queue_id,
            pkts,
            max_num_pkts);
    if (num_recv_pkts == 0) {
        //RTE_LOG(DEBUG, USER1, "No packets received on port: %u, queue: %u\n",
        //        port_id, queue_id);
        return;
    }

    /* Classify all the packets one by one */
    packdev_packet_classify_bulk(pkts, num_recv_pkts, port_id);
}

static void packdev_packet_flush_on_queue(
        uint8_t port_id,
        uint16_t queue_id) {
    packdev_port_t *port_data = packdev_port_get(port_id);
    assert(port_data != NULL);

    struct mbuf_table *mtab = &port_data->tx_queue[queue_id].tx_mbufs;
    struct rte_mbuf **pkts = mtab->m_table;
    uint32_t cnt = mtab->len;
    uint32_t ret;

    // Send all packets in tx_mbufs
    while (cnt > 0) {
        ret = rte_eth_tx_burst(port_id, queue_id, pkts, cnt);

        pkts += ret;
        cnt -= ret;
    }

    // Reset tx_mbufs
    mtab->len = 0;
}

void packdev_packet_flush_all(uint8_t port_id) {
    packdev_port_t *port_data = packdev_port_get(port_id);
    assert(port_data != NULL);

    for (uint16_t queue_id = 0;
            queue_id < port_data->num_tx_queues;
            ++queue_id) {
        packdev_packet_flush_on_queue(port_id, queue_id);
    }
}

void packdev_packet_send(
        struct rte_mbuf *packet,
        uint8_t port_id,
        uint16_t queue_id) {
    packdev_port_t *port_data = packdev_port_get(port_id);
    assert(port_data != NULL);

    struct mbuf_table *mtab = &port_data->tx_queue[queue_id].tx_mbufs;

    /* Add packet to the TX list. */
    mtab->m_table[mtab->len++] = packet;

    /* Flush if we have reached max tx_mbufs size */
    if (mtab->len >= port_data->tx_burst)
        packdev_packet_flush_on_queue(port_id, queue_id);
}
