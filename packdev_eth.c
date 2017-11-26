
/* Fast Path packet processing prototype

   see also: ip_fastpath.h

   sven.s.stenstrom@ericsson.com

 */

#include <stdint.h>
#include <unistd.h>

#include <rte_mbuf.h>
#include <rte_ether.h>

#include "packdev_common.h"
#include "packdev_packet.h"
#include "packdev_eth.h"
#include "packdev_vlan.h"
#include "packdev_ipv4.h"

void packdev_eth_build(struct rte_mbuf *packet) {
    struct ether_hdr *eth_hdr =
        (struct ether_hdr*)rte_pktmbuf_prepend(packet, sizeof(struct ether_hdr));
    eth_random_addr(eth_hdr->s_addr.addr_bytes);
    eth_random_addr(eth_hdr->d_addr.addr_bytes);
    eth_hdr->ether_type = rte_bswap16(ETHER_TYPE_IPv4);

    // TODO: QUEUEID: fix lcore id to rx/tx queue id
    packdev_packet_send(packet, packet->port, 0);
}

void packdev_eth_process(struct rte_mbuf *packet) {
    struct ether_hdr *eth_hdr = MBUF_ETH_HDR_PTR(packet);
    uint16_t ether_type = rte_bswap16(eth_hdr->ether_type);
    packdev_eth_print_addr(eth_hdr->s_addr);
    packdev_eth_print_addr(eth_hdr->d_addr);

    if (rte_pktmbuf_adj(packet, OFF_ETH_HDR) == NULL) {
        RTE_LOG(ERR, USER1,
                "PACKET: Failed to remove ethernet header, dropping packet!!!\n");
        rte_pktmbuf_free(packet);
        return;
    }

    switch (ether_type) {
    case ETHER_TYPE_VLAN:
        /* Frees the mbuf */
        packdev_vlan_process(packet);
        break;
    case ETHER_TYPE_IPv4:
        /* Frees the mbuf */
        packdev_ipv4_process(packet);
        break;
    default:
        RTE_LOG(INFO, USER1, "Unknown ether type: %u\n", ether_type);
        RTE_LOG(INFO, USER1, "Do not know how to handle ether type: %u\n", ether_type);
        rte_pktmbuf_free(packet);
        break;
    }
}

void packdev_eth_print_addr(struct ether_addr addr) {
    RTE_LOG(DEBUG, USER1,
            "MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
            " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
            addr.addr_bytes[0], addr.addr_bytes[1],
            addr.addr_bytes[2], addr.addr_bytes[3],
            addr.addr_bytes[4], addr.addr_bytes[5]);
}
