
/* Fast Path packet processing prototype

   see also: ip_fastpath.h

   sven.s.stenstrom@ericsson.com

 */

#include <sys/types.h>
#include <stdint.h>
#include <stdbool.h>
#include <strings.h>
#include <assert.h>

#include <rte_eal.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_acl.h>
#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_ip_frag.h>
#include <rte_ether.h>
#include <rte_debug.h>

#include "packdev_eth.h"
#include "packdev_acl.h"
#include "packdev_acl_config.h"
#include "packdev_common.h"
#include "packdev_esp.h"
#include "packdev_udp.h"
#include "packdev_packet.h"

#include "packdev_ipv4.h"

struct rte_ip_frag_tbl *global_frag_table;
struct rte_ip_frag_death_row death_row;

static bool is_checksum_correct(struct ipv4_hdr *ipv4_hdr) {
    uint16_t orig_checksum = ipv4_hdr->hdr_checksum;
    ipv4_hdr->hdr_checksum = 0;
    return (orig_checksum == rte_ipv4_cksum(ipv4_hdr));
}

static struct rte_mbuf* fragment_process(
        struct rte_mbuf *packet,
        uint64_t current_timestamp) {
    struct ipv4_hdr *ipv4_hdr = MBUF_IPV4_HDR_PTR(packet);
    if (rte_ipv4_frag_pkt_is_fragmented(ipv4_hdr) == 0) {
        RTE_LOG(DEBUG, USER1, "IPv4 packet is not fragmented\n");
        return packet;
    }

    RTE_LOG(DEBUG, USER1, "IPv4 packet is fragmented\n");
    struct rte_mbuf *reassembled_packet;
    /* prepare mbuf: setup l2_len/l3_len. */
    packet->l2_len = 0;
    packet->l3_len = sizeof(struct ipv4_hdr);
    /* process this fragment. */
    reassembled_packet = rte_ipv4_frag_reassemble_packet(
            global_frag_table,
            &death_row,
            packet,
            current_timestamp,
            ipv4_hdr);
    if (reassembled_packet == NULL) {
        /* all fragments not received yet. */
        return NULL;
    }

    /* we have our packet reassembled. */
    if (reassembled_packet != packet) {
        packet = reassembled_packet;
        return packet;
    }

    RTE_LOG(NOTICE, USER1, "IPv4 reassembly failed!!!\n");
    return NULL;
}

static void ipv4_downlink_process(struct rte_mbuf *packet) {
    uint64_t current_timestamp = rte_rdtsc();
    struct ipv4_hdr *ipv4_hdr = MBUF_IPV4_HDR_PTR(packet);
    RTE_LOG(DEBUG, USER1, "IPv4 packet received!\n");
    RTE_LOG(DEBUG, USER1, "IPv4 src address\n");
    packdev_ipv4_print_addr(rte_bswap32(ipv4_hdr->src_addr));
    RTE_LOG(DEBUG, USER1, "IPv4 dst address\n");
    packdev_ipv4_print_addr(rte_bswap32(ipv4_hdr->dst_addr));
    //rte_pktmbuf_dump(stdout, packet, packet->data_len);

    if (!is_checksum_correct(ipv4_hdr)) {
        RTE_LOG(NOTICE, USER1, "IPv4 checksum incorrect, dropping packet\n");
        return;
    }

    // TODO: No reassembly on inner packets yet.
    packdev_metadata_t *metadata = PACKDEV_METADATA_PTR(packet);
    if (metadata->inner_packet == false &&
            (packet = fragment_process(packet, current_timestamp)) == NULL) {
        RTE_LOG(DEBUG, USER1, "IPv4 reassembly not completed yet\n");
        return;
    }

    switch(ipv4_hdr->next_proto_id) {
    case IPPROTO_UDP:
        RTE_LOG(INFO, USER1, "UDP packet received!\n");
        packdev_udp_process(packet);
        break;
    case IPPROTO_ICMP:
        RTE_LOG(INFO, USER1, "ICMP packet received!\n");
        packdev_eth_build(packet);
        break;
    case IPPROTO_ESP:
        RTE_LOG(INFO, USER1, "ESP packet received!\n");
        if (metadata->inner_packet) {
            RTE_LOG(INFO, USER1, "ESP inside ESP received, dropping packet!\n");
            rte_pktmbuf_free(packet);
        } else {
            packdev_esp_process(packet);
        }
        break;
    default:
        RTE_LOG(INFO, USER1, "IPv4 next protocol ID 0x%x\n", ipv4_hdr->next_proto_id);
        rte_pktmbuf_free(packet);
        break;
    };
}

void packdev_ipv4_process(struct rte_mbuf *packet) {
    // No ACL on inner packet
    packdev_metadata_t *metadata = PACKDEV_METADATA_PTR(packet);
    if (metadata->inner_packet) {
        ipv4_downlink_process(packet);
        return;
    }

    uint32_t acl_result = packdev_acl_classify(packet);
    RTE_LOG(DEBUG, USER1, "Results from ACL: %u\n", acl_result);

    switch(acl_result) {
    case PACKDEV_ACL_NO_MATCH:
        RTE_LOG(INFO, USER1, "No match found, allowing packet to bypass ACL\n");
    case PACKDEV_ACL_ACCEPT:
        ipv4_downlink_process(packet);
        break;
    case PACKDEV_ACL_DENY:
    default:
        RTE_LOG(INFO, USER1,
                "ACL result is not accept, so dropping the packet\n");
        rte_pktmbuf_free(packet);
        break;
    };
}

void packdev_ipv4_print_addr(uint32_t addr) {
    uint8_t addr_bytes[4] = {
        (addr >> 24) & 0xff,
        (addr >> 16) & 0xff,
        (addr >> 8)  & 0xff,
        (addr)       & 0xff,
    };

    RTE_LOG(DEBUG, USER1, "IPv4: %u.%u.%u.%u\n",
            addr_bytes[0], addr_bytes[1], addr_bytes[2], addr_bytes[3]);
}

void packdev_ipv4_init() {
    // TODO: Understand this ip reassembly magic
    uint64_t frag_cycles =
        (rte_get_tsc_hz() + MS_PER_S - 1) / MS_PER_S * REASSEMBLY_TIMER_MS;
    global_frag_table = rte_ip_frag_table_create(
            MAX_REASSEMBLY_FLOWS,
            MAX_REASSEMBLY_FRAGMENTS,
            MAX_REASSEMBLY_FLOWS * MAX_REASSEMBLY_FRAGMENTS,
            frag_cycles,
            SOCKET_ID_ANY);

    if (global_frag_table == NULL) {
        rte_exit(EXIT_FAILURE, "IPv4: cannot create fragmentation table\n");
    }
}
