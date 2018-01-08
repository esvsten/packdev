
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
#include <rte_icmp.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_acl.h>
#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_ip_frag.h>
#include <rte_ether.h>
#include <rte_debug.h>

#include "sys/packdev_common.h"
#include "sys/packdev_config.h"
#include "sys/packdev_packet.h"
#include "sys/packdev_port.h"

#include "cp/packdev_acl_config.h"
#include "cp/packdev_ipv4_flow.h"
#include "cp/packdev_l3_config.h"

#include "fp/packdev_eth.h"
#include "fp/packdev_esp.h"
#include "fp/packdev_udp.h"
#include "fp/packdev_ipv4.h"

struct rte_ip_frag_tbl *global_frag_table;
struct rte_ip_frag_death_row death_row;

static uint16_t calculate_l4_checksum(
        struct rte_mbuf *packet) {
    struct ipv4_hdr *ipv4_hdr = MBUF_IPV4_HDR_PTR(packet);

    void *data_ptr = rte_pktmbuf_mtod_offset((packet), void*, sizeof(struct ipv4_hdr));
    uint32_t checksum = rte_raw_cksum(data_ptr, packet->data_len - sizeof(struct ipv4_hdr));
    struct rte_mbuf *segment = packet->next;

    while (segment != NULL) {
        data_ptr = rte_pktmbuf_mtod(segment, void*);
        checksum += rte_raw_cksum(data_ptr, segment->data_len);
        segment = segment->next;
    }

    checksum += rte_ipv4_phdr_cksum(ipv4_hdr, 0);

    checksum = ((checksum & 0xffff0000) >> 16) + (checksum & 0xffff);
    checksum = (~checksum) & 0xffff;
    if (checksum == 0) {
        checksum = 0xffff;
    }

    return (uint16_t)checksum;
}

static void set_l4hdr_checksum(struct rte_mbuf *packet) {
    struct ipv4_hdr *ipv4_hdr = MBUF_IPV4_HDR_PTR(packet);
    uint16_t original_checksum = ipv4_hdr->hdr_checksum;
    ipv4_hdr->hdr_checksum = 0;
    switch(ipv4_hdr->next_proto_id) {
    case IPPROTO_UDP:
        RTE_LOG(DEBUG, USER1, "IPv4: Set UDP checksum\n");
        struct udp_hdr *udp_hdr = MBUF_IPV4_UDP_HDR_PTR(packet);
        //RTE_LOG(DEBUG, USER1, "old (0x%x), ", rte_be_to_cpu_16(udp_hdr->dgram_cksum));
        udp_hdr->dgram_cksum = 0;
        udp_hdr->dgram_cksum = calculate_l4_checksum(packet);
        //RTE_LOG(DEBUG, USER1, "new (0x%x)\n", rte_be_to_cpu_16(udp_hdr->dgram_cksum));
        break;
    case IPPROTO_TCP:
        RTE_LOG(DEBUG, USER1, "IPv4: Set TCP checksum\n");
        struct tcp_hdr *tcp_hdr = MBUF_IPV4_TCP_HDR_PTR(packet);
        //RTE_LOG(DEBUG, USER1, "old (0x%x), ", rte_be_to_cpu_16(tcp_hdr->cksum));
        tcp_hdr->cksum = 0;
        tcp_hdr->cksum = calculate_l4_checksum(packet);
        //RTE_LOG(DEBUG, USER1, "new (0x%x)\n", rte_be_to_cpu_16(tcp_hdr->cksum));
        break;
    default:
        break;
    }
    ipv4_hdr->hdr_checksum = original_checksum;
}

static void set_ipv4_checksum(struct rte_mbuf *packet) {
    RTE_LOG(DEBUG, USER1, "IPv4: Set header checksum\n");
    struct ipv4_hdr *ipv4_hdr = MBUF_IPV4_HDR_PTR(packet);
    ipv4_hdr->hdr_checksum = 0;
    ipv4_hdr->hdr_checksum = rte_ipv4_cksum(ipv4_hdr);
}

static bool is_checksum_correct(struct ipv4_hdr *ipv4_hdr) {
    uint16_t orig_checksum = ipv4_hdr->hdr_checksum;
    ipv4_hdr->hdr_checksum = 0;
    bool result = (orig_checksum == rte_ipv4_cksum(ipv4_hdr));

    ipv4_hdr->hdr_checksum = orig_checksum;
    return result;
}

static struct rte_mbuf* fragment_process(
        struct rte_mbuf *packet,
        uint64_t current_timestamp) {
    struct ipv4_hdr *ipv4_hdr = MBUF_IPV4_HDR_PTR(packet);
    if (rte_ipv4_frag_pkt_is_fragmented(ipv4_hdr) == 0) {
        RTE_LOG(DEBUG, USER1, "IPv4: packet is not fragmented\n");
        return packet;
    }

    RTE_LOG(DEBUG, USER1, "IPv4: packet is fragmented\n");
    if (death_row.cnt >= DEFAULT_PKT_BURST) {
        RTE_LOG(DEBUG, USER1, "IPv4: death row count: %u\n", death_row.cnt);
        rte_ip_frag_free_death_row(&death_row, 3);
    }

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
        RTE_LOG(INFO, USER1, "IPv4: reassembly successful!!\n");
        ipv4_hdr = MBUF_IPV4_HDR_PTR(packet);
        RTE_LOG(DEBUG, USER1, "IPv4 reassembled length (%u)\n",
                rte_be_to_cpu_16(ipv4_hdr->total_length));
        //rte_pktmbuf_dump(stdout, packet, packet->data_len);
        return packet;
    }

    RTE_LOG(NOTICE, USER1, "IPv4: reassembly failed!!!\n");
    return NULL;
}

// switch packets between NIC/VETH
static void ipv4_switch_packet(struct rte_mbuf *packet) {
    packdev_metadata_t *metadata = PACKDEV_METADATA_PTR(packet);
    struct ipv4_hdr *ipv4_hdr = MBUF_IPV4_HDR_PTR(packet);
    metadata->next_hop_ipv4_addr = rte_be_to_cpu_32(ipv4_hdr->dst_addr);
    if (metadata->origin == PACKDEV_ORIGIN_NIC ||
            metadata->origin == PACKDEV_ORIGIN_VETH) {
        packdev_eth_build(packet);
    } else {
        RTE_LOG(ERR, USER1, "IPv4: FP originated packet cannot be switched\n");
        rte_pktmbuf_free(packet);
    }
}

static void ipv4_uplink_process(struct rte_mbuf *packet) {
    packdev_metadata_t *metadata = PACKDEV_METADATA_PTR(packet);
    struct ipv4_hdr *ipv4_hdr = MBUF_IPV4_HDR_PTR(packet);
    RTE_LOG(DEBUG, USER1, "IPv4 uplink packet received!\n");
    RTE_LOG(DEBUG, USER1, "IPv4 src address\n");
    packdev_ipv4_print_addr(rte_be_to_cpu_32(ipv4_hdr->src_addr));
    RTE_LOG(DEBUG, USER1, "IPv4 dst address\n");
    packdev_ipv4_print_addr(rte_be_to_cpu_32(ipv4_hdr->dst_addr));
    RTE_LOG(DEBUG, USER1, "IPv4 total length (%u)\n", rte_be_to_cpu_16(ipv4_hdr->total_length));
    //rte_pktmbuf_dump(stdout, packet, packet->data_len);

    if (metadata->origin != PACKDEV_ORIGIN_VETH) {
        RTE_LOG(ERR, USER1, "IPv4: FP/NIC originated uplink packets cannot be handled\n");
        rte_pktmbuf_free(packet);
        return;
    }

    packdev_l3_if_t *l3_if =
        packdev_l3_config_get_using_ipv4_addr(rte_be_to_cpu_32(ipv4_hdr->src_addr));
    if (l3_if == NULL) {
        RTE_LOG(NOTICE, USER1, "IPv4: Unable to find L3 interface for the source IPv4 address\n");
        rte_pktmbuf_free(packet);
        return;
    } else {
        metadata->output_l3_if_id = l3_if->if_id;
        metadata->output_l2_if_id = l3_if->attr.l2_if_id;
    }

    // Set checksum
    set_l4hdr_checksum(packet);

    // Check routing table and fill in next hop address
    struct next_hop_attr_t *nh =
        packdev_l3_get_next_hop(rte_be_to_cpu_32(ipv4_hdr->dst_addr));
    if (nh != NULL) {
        metadata->output_l3_if_id = nh->l3_if_id;
        if (nh->gateway) {
            metadata->next_hop_ipv4_addr = nh->gateway;
        } else {
            // connected route
            metadata->next_hop_ipv4_addr = rte_be_to_cpu_32(ipv4_hdr->dst_addr);
        }
    } else {
        RTE_LOG(ERR, USER1, "IPv4: No route found to destination\n");
        rte_pktmbuf_free(packet);
        return;
    }

    struct rte_mbuf *fragments[MAX_NUM_FRAGMENTS];
    int32_t num_fragments = 0;
    if (packet->pkt_len > l3_if->attr.mtu) {
        RTE_LOG(DEBUG, USER1,
                "IPv4: Fragmenting packet greater than MTU (%u)\n", l3_if->attr.mtu);
        num_fragments = rte_ipv4_fragment_packet(
                packet,
                fragments,
                MAX_NUM_FRAGMENTS,
                l3_if->attr.mtu,
                packdev_port_get_tx_mp(),
                packdev_port_get_tx_indirect_mp());

        switch(num_fragments) {
            case -ENOMEM:
                RTE_LOG(ERR, USER1, "IPv4: Fragmentation failed, dropping packet!!!\n");
                rte_pktmbuf_free(packet);
                return;
            case -ENOTSUP:
                RTE_LOG(ERR, USER1, "IPv4: DF bit set, cannot fragment, dropping packet!!!\n");
                rte_pktmbuf_free(packet);
                return;
            case -EINVAL:
                RTE_LOG(ERR, USER1, "IPv4: Number of fragments needed greater than max allowed: %u\n",
                        MAX_NUM_FRAGMENTS);
                rte_pktmbuf_free(packet);
                return;
            default:
                RTE_LOG(DEBUG, USER1, "IPv4: Fragmentation successful, number of fragments: %u\n",
                        num_fragments);
                break;
        }

        for (uint8_t frag_index = 0; frag_index < num_fragments; ++frag_index) {
            struct rte_mbuf *fragment = fragments[frag_index];
            PACKDEV_METADATA_COPY(fragment, packet);
            packdev_metadata_t *fragment_metadata = PACKDEV_METADATA_PTR(fragment);
            set_ipv4_checksum(fragment);

            ipv4_hdr = MBUF_IPV4_HDR_PTR(fragment);
            RTE_LOG(DEBUG, USER1, "IPv4 fragment length (%u)\n",
                    rte_be_to_cpu_16(ipv4_hdr->total_length));

            packdev_esp_build(fragment);
            if (!fragment_metadata->consumed) {
                packdev_eth_build(fragment);
            }
        }
        rte_pktmbuf_free(packet);
    } else {
        set_ipv4_checksum(packet);
        packdev_esp_build(packet);
        if (!metadata->consumed) {
            packdev_eth_build(packet);
        }
    }
}

static void ipv4_downlink_process(struct rte_mbuf *packet) {
    uint64_t current_timestamp = rte_rdtsc();
    struct ipv4_hdr *ipv4_hdr = MBUF_IPV4_HDR_PTR(packet);
    RTE_LOG(DEBUG, USER1, "IPv4 downlink packet received!\n");
    RTE_LOG(DEBUG, USER1, "IPv4 src address\n");
    packdev_ipv4_print_addr(rte_be_to_cpu_32(ipv4_hdr->src_addr));
    RTE_LOG(DEBUG, USER1, "IPv4 dst address\n");
    packdev_ipv4_print_addr(rte_be_to_cpu_32(ipv4_hdr->dst_addr));
    RTE_LOG(DEBUG, USER1, "IPv4 total length (%u)\n", rte_be_to_cpu_16(ipv4_hdr->total_length));
    //rte_pktmbuf_dump(stdout, packet, packet->data_len);

    // Trim ethernet padding bytes
    // TODO 2018-01-07: Move this logic to ethernet module
    uint32_t ipv4_length = rte_be_to_cpu_16(ipv4_hdr->total_length);
    if (rte_pktmbuf_pkt_len(packet) > ipv4_length) {
        rte_pktmbuf_trim(packet,
                rte_pktmbuf_pkt_len(packet) - ipv4_length);
    }

    packdev_l3_if_t *l3_if =
        packdev_l3_config_get_using_ipv4_addr(rte_be_to_cpu_32(ipv4_hdr->dst_addr));
    if (l3_if == NULL) {
        RTE_LOG(NOTICE, USER1, "IPv4: Unable to find L3 interface for the destination IPv4 address\n");
        rte_pktmbuf_free(packet);
        return;
    }

    packdev_metadata_t *metadata = PACKDEV_METADATA_PTR(packet);
    metadata->input_l3_if_id = l3_if->if_id;
    // Output L3 interface ID might change during packet processing
    metadata->output_l3_if_id = l3_if->if_id;

    if (!is_checksum_correct(ipv4_hdr)) {
        RTE_LOG(NOTICE, USER1, "IPv4: checksum incorrect, dropping packet\n");
        rte_pktmbuf_free(packet);
        return;
    }

    // TODO: No reassembly on inner packets yet.
    if (metadata->inner_packet == false &&
            (packet = fragment_process(packet, current_timestamp)) == NULL) {
        RTE_LOG(DEBUG, USER1, "IPv4: reassembly not completed yet\n");
        return;
    } else {
        // Some PMDs do not support segmented buffers, try to linearize
        // For e.g. openssl PMD
        if (rte_pktmbuf_linearize(packet) < 0) {
            RTE_LOG(NOTICE, USER1, "IPv4: Could not linearize segmented buffer\n");
        }

        set_l4hdr_checksum(packet);
        set_ipv4_checksum(packet);
    }

    switch(ipv4_hdr->next_proto_id) {
    case IPPROTO_UDP:
        RTE_LOG(INFO, USER1, "UDP packet received!\n");
        packdev_udp_process(packet);
        if (metadata->consumed) {
            // TODO 2018-01-04: Free the packet after sending via fast path sockets
            rte_pktmbuf_free(packet);
        } else {
            ipv4_switch_packet(packet);
        }
        break;
    case IPPROTO_TCP:
        RTE_LOG(INFO, USER1, "TCP packet received!\n");
        struct tcp_hdr *tcp_hdr = MBUF_IPV4_TCP_HDR_PTR(packet);
        RTE_LOG(DEBUG, USER1, "TCP: src port: %u\n", rte_be_to_cpu_16(tcp_hdr->src_port));
        RTE_LOG(DEBUG, USER1, "TCP: dst port: %u\n", rte_be_to_cpu_16(tcp_hdr->dst_port));
        RTE_LOG(DEBUG, USER1, "TCP: sequence number: %u\n", rte_be_to_cpu_32(tcp_hdr->sent_seq));
        ipv4_switch_packet(packet);
        break;
    case IPPROTO_ICMP:
        RTE_LOG(INFO, USER1, "ICMP packet received!\n");
        struct icmp_hdr *icmp_hdr = MBUF_IPV4_ICMP_HDR_PTR(packet);
        RTE_LOG(DEBUG, USER1, "ICMP: type: %u\n", icmp_hdr->icmp_type);
        RTE_LOG(DEBUG, USER1, "ICMP: identity: %u\n", rte_be_to_cpu_16(icmp_hdr->icmp_ident));
        RTE_LOG(DEBUG, USER1, "ICMP: checksum: 0x%x\n", rte_be_to_cpu_16(icmp_hdr->icmp_cksum));
        RTE_LOG(DEBUG, USER1, "ICMP: sequence number: %u\n", rte_be_to_cpu_16(icmp_hdr->icmp_seq_nb));
        ipv4_switch_packet(packet);
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
        RTE_LOG(INFO, USER1, "IPv4: next protocol ID 0x%x\n", ipv4_hdr->next_proto_id);
        rte_pktmbuf_free(packet);
        break;
    };
}

void packdev_ipv4_process(struct rte_mbuf *packet) {
    uint32_t acl_result = PACKDEV_ACL_NO_MATCH;

    // No ACL on inner packet
    packdev_metadata_t *metadata = PACKDEV_METADATA_PTR(packet);
    if (!metadata->inner_packet) {
        // TODO: split ingress/egress ACL rules
        acl_result = packdev_ipv4_flow_classify(PACKDEV_FLOW_TYPE_ACL, packet);
        RTE_LOG(DEBUG, USER1, "Results from ACL: %u\n", acl_result);
    }

    switch(acl_result) {
    case PACKDEV_ACL_NO_MATCH:
        RTE_LOG(INFO, USER1, "No match found, allowing packet to bypass ACL\n");
    case PACKDEV_ACL_ACCEPT:
        if (metadata->direction == PACKDEV_INGRESS) {
            ipv4_downlink_process(packet);
        } else {
            ipv4_uplink_process(packet);
        }
        break;
    case PACKDEV_ACL_DENY:
    default:
        RTE_LOG(INFO, USER1,
                "ACL result is deny, so dropping the packet\n");
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
