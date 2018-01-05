
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
#include <rte_udp.h>
#include <rte_common.h>

#include "sys/packdev_common.h"
#include "sys/packdev_packet.h"

#include "cp/packdev_ipv4_flow.h"
#include "cp/packdev_session.h"

#include "fp/packdev_eth.h"
#include "fp/packdev_udp.h"

void packdev_udp_process(struct rte_mbuf *packet) {
    packdev_metadata_t *metadata = PACKDEV_METADATA_PTR(packet);
    //struct ipv4_hdr *ipv4_hdr = MBUF_IPV4_HDR_PTR(packet);
    struct udp_hdr *udp_hdr = MBUF_IPV4_UDP_HDR_PTR(packet);
    RTE_LOG(DEBUG, USER1, "UDP: src_port=%u\n", rte_be_to_cpu_16(udp_hdr->src_port));
    RTE_LOG(DEBUG, USER1, "UDP: dst_port=%u\n", rte_be_to_cpu_16(udp_hdr->dst_port));
    RTE_LOG(DEBUG, USER1, "UDP: data length=%u\n", rte_be_to_cpu_16(udp_hdr->dgram_len));

    uint32_t session_result = packdev_ipv4_flow_classify(PACKDEV_FLOW_TYPE_SESSION, packet);
    switch(session_result) {
    case PACKDEV_SESSION_SEND_TO_FP:
        RTE_LOG(DEBUG, USER1, "UDP: Send to FP for further processing\n");
        metadata->consumed = true;
        break;
    case PACKDEV_SESSION_SEND_TO_CPU:
        RTE_LOG(DEBUG, USER1, "UDP: Send to IPv4 for further processing\n");
        break;
    case PACKDEV_SESSION_NO_MATCH:
    default:
        RTE_LOG(INFO, USER1, "UDP: No match found, dropping the packet!!!\n");
        metadata->consumed = true;
        break;
    };
}
