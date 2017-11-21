
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
#include <rte_common.h>

#include "packdev_common.h"
#include "packdev_acl.h"
#include "packdev_session.h"
#include "packdev_packet.h"
#include "packdev_udp.h"

static uint32_t udp_session_lookup(
        uint32_t src_addr,
        uint32_t dst_addr,
        uint16_t src_port,
        uint16_t dst_port) {
    uint32_t session_id = 0;
    ipv4_session_config_t session = {
        .src_addr = src_addr,
        .dst_addr = dst_addr,
        .src_port = src_port,
        .dst_port = dst_port,
    };

    uint32_t key = rte_jhash(&session, sizeof(session), SESSION_IV);
    RTE_LOG(DEBUG, USER1, "Session: Received packet with key = 0x%08x\n", key);

    int lookup_result = rte_hash_lookup_data(
            packdev_session_get_table(),
            &key,
            (void**)(&session_id));
    if (lookup_result >= 0) {
        return session_id;
    }

    switch(lookup_result) {
    case -ENOENT:
        RTE_LOG(DEBUG, USER1, "Session: Key not found\n");
        break;
    case -EINVAL:
        RTE_LOG(DEBUG, USER1, "Session: Invalid hash parameter\n");
        break;
    default:
        RTE_LOG(DEBUG, USER1, "Session: Unexpected error on lookup (%d)\n", lookup_result);
        break;
    };

    return 0;
}

void packdev_udp_process(
        struct rte_mbuf *packet,
        uint16_t port_id) {
    struct ipv4_hdr *ipv4_hdr = (struct ipv4_hdr*)MBUF_IP_HDR_OFFSET(packet);
    struct udp_hdr *udp_hdr = (struct udp_hdr*)MBUF_IPV4_UDP_HDR_OFFSET(packet);
    uint32_t session_id = udp_session_lookup(
            rte_bswap32(ipv4_hdr->src_addr),
            rte_bswap32(ipv4_hdr->dst_addr),
            rte_bswap16(udp_hdr->src_port),
            rte_bswap16(udp_hdr->dst_port));

    if (session_id == 0) {
        RTE_LOG(NOTICE, USER1, "UDP session not found, dropping packet!!!\n");
        rte_pktmbuf_free(packet);
        return;
    }

    // TODO: QUEUEID: fix lcore id to rx/tx queue id
    RTE_LOG(INFO, USER1, "UDP session found (%u)\n", session_id);
    packdev_packet_send(packet, port_id, 0);
}
