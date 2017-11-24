
/* Fast Path packet processing prototype

   see also: ip_fastpath.h

   sven.s.stenstrom@ericsson.com

 */

#include <sys/types.h>
#include <stdint.h>
#include <stdbool.h>

#include <rte_eal.h>
#include <rte_mbuf.h>
#include <rte_common.h>
#include <rte_ether.h>
#include <rte_debug.h>

#include "packdev_eth.h"
#include "packdev_common.h"
#include "packdev_packet.h"
#include "packdev_ipv4.h"

#include "packdev_vlan.h"

void packdev_vlan_process(
        struct rte_mbuf *packet,
        uint16_t port_id) {
    struct vlan_hdr *vlan_hdr = (struct vlan_hdr *)MBUF_VLAN_HDR_OFFSET(packet);
    RTE_LOG(DEBUG, USER1, "VLAN: Received packet with tag: %u\n",
            rte_bswap16(vlan_hdr->vlan_tci));

    if (rte_bswap16(vlan_hdr->eth_proto) != ETHER_TYPE_IPv4) {
        RTE_LOG(ERR, USER1, "VLAN: Unknown ether type: %u\n", vlan_hdr->eth_proto);
        goto clean_up;
    }

    if (rte_vlan_strip(packet) < 0) {
        RTE_LOG(ERR, USER1, "VLAN: Failed to strip VLAN header\n");
        goto clean_up;
    }

    packdev_ipv4_process(packet, port_id, false /* inner packet */);

clean_up:
    rte_pktmbuf_free(packet);
}
