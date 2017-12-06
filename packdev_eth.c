
/* Fast Path packet processing prototype

   see also: ip_fastpath.h

   sven.s.stenstrom@ericsson.com

 */

#include <stdint.h>
#include <unistd.h>

#include <rte_mbuf.h>
#include <rte_arp.h>
#include <rte_ether.h>

#include "packdev_common.h"
#include "packdev_config.h"
#include "packdev_l2_config.h"
#include "packdev_nbr.h"
#include "packdev_packet.h"
#include "packdev_eth.h"
#include "packdev_ipv4.h"
#include "packdev_port.h"

static void arp_build_request(
        struct rte_mbuf *original_packet,
        packdev_l2_if_t* l2_if,
        uint32_t src_ipv4_addr) {
    struct rte_mbuf *packet = rte_pktmbuf_alloc(packdev_port_get_tx_mp());

    struct ether_hdr *original_eth_hdr = MBUF_ETH_HDR_PTR(original_packet);
    struct ether_hdr *eth_hdr = MBUF_ETH_HDR_PTR(packet);
    uint32_t packet_length = OFF_ETH_HDR;
    ether_addr_copy(&original_eth_hdr->s_addr, &eth_hdr->s_addr);
    memset(&eth_hdr->d_addr.addr_bytes, 0xFF, ETHER_ADDR_LEN);
    eth_hdr->ether_type = rte_cpu_to_be_16(ETHER_TYPE_ARP);

    struct arp_hdr *arp_hdr;
    packet_length += OFF_ARP_HDR;
    if (l2_if->attr.vlan_id != 0) {
        packet->vlan_tci = l2_if->attr.vlan_id;
        rte_vlan_insert(&packet);
        eth_hdr = MBUF_ETH_HDR_PTR(packet);
        arp_hdr = MBUF_ARP_VLAN_HDR_PTR(packet);
        packet_length += OFF_VLAN_HDR;
    } else {
        arp_hdr = MBUF_ARP_HDR_PTR(packet);
    }
    arp_hdr->arp_hrd = rte_cpu_to_be_16(ARP_HRD_ETHER);
    arp_hdr->arp_pro = rte_cpu_to_be_16(ETHER_TYPE_IPv4);
    arp_hdr->arp_hln = ETHER_ADDR_LEN;
    arp_hdr->arp_pln = sizeof(arp_hdr->arp_data.arp_sip);
    arp_hdr->arp_op = rte_cpu_to_be_16(ARP_OP_REQUEST);

    // add source hardware address
    ether_addr_copy(&original_eth_hdr->s_addr, &arp_hdr->arp_data.arp_sha);
    // add source ipv4 address
    arp_hdr->arp_data.arp_sip = rte_cpu_to_be_32(src_ipv4_addr);
    // add destination hardware address
    memset(&arp_hdr->arp_data.arp_tha.addr_bytes, 0x00, ETHER_ADDR_LEN);
    // add destination ipv4 address
    packdev_metadata_t *original_metadata = PACKDEV_METADATA_PTR(original_packet);
    arp_hdr->arp_data.arp_tip = rte_cpu_to_be_32(original_metadata->next_hop_ipv4_addr);

    packet->port = l2_if->attr.port_id;
    packet->l2_len = OFF_ETH_HDR;
    packet->pkt_len = RTE_MAX(packet_length, ETHER_MIN_LEN - ETHER_CRC_LEN);
    packet->data_len = RTE_MAX(packet_length, ETHER_MIN_LEN - ETHER_CRC_LEN);

    packdev_packet_send(packet, l2_if->attr.port_id, 0);
    rte_pktmbuf_free(original_packet);
    RTE_LOG(DEBUG, USER1, "ARP: Sent request\n");
}

static void arp_build_reply(
        struct rte_mbuf *original_packet,
        packdev_l2_if_t* l2_if) {
    struct rte_mbuf *packet = rte_pktmbuf_alloc(packdev_port_get_tx_mp());

    struct ether_hdr *original_eth_hdr = MBUF_ETH_HDR_PTR(original_packet);
    struct ether_hdr *eth_hdr = MBUF_ETH_HDR_PTR(packet);
    uint32_t packet_length = OFF_ETH_HDR;
    ether_addr_copy(&original_eth_hdr->s_addr, &eth_hdr->d_addr);
    memcpy(eth_hdr->s_addr.addr_bytes, l2_if->attr.mac_addr, sizeof(l2_if->attr.mac_addr));
    eth_hdr->ether_type = rte_cpu_to_be_16(ETHER_TYPE_ARP);

    struct arp_hdr *original_arp_hdr = NULL;
    struct arp_hdr *arp_hdr = NULL;
    packet_length += OFF_ARP_HDR;
    if (l2_if->attr.vlan_id != 0) {
        packet->vlan_tci = l2_if->attr.vlan_id;
        rte_vlan_insert(&packet);
        eth_hdr = MBUF_ETH_HDR_PTR(packet);
        arp_hdr = MBUF_ARP_VLAN_HDR_PTR(packet);
        original_arp_hdr = MBUF_ARP_VLAN_HDR_PTR(original_packet);
        packet_length += OFF_VLAN_HDR;
        packet->l2_len = OFF_ETH_HDR + OFF_VLAN_HDR;
    } else {
        arp_hdr = MBUF_ARP_HDR_PTR(packet);
        original_arp_hdr = MBUF_ARP_HDR_PTR(original_packet);
        packet->l2_len = OFF_ETH_HDR;
    }
    arp_hdr->arp_hrd = rte_cpu_to_be_16(ARP_HRD_ETHER);
    arp_hdr->arp_pro = rte_cpu_to_be_16(ETHER_TYPE_IPv4);
    arp_hdr->arp_hln = ETHER_ADDR_LEN;
    arp_hdr->arp_pln = sizeof(arp_hdr->arp_data.arp_sip);
    arp_hdr->arp_op = rte_cpu_to_be_16(ARP_OP_REPLY);

    // add source hardware address
    ether_addr_copy(&eth_hdr->s_addr, &arp_hdr->arp_data.arp_sha);
    // add source ipv4 address
    // TODO: Add support for L3 interfaces and routes
    arp_hdr->arp_data.arp_sip = original_arp_hdr->arp_data.arp_tip;
    // add destination hardware address
    ether_addr_copy(&eth_hdr->d_addr, &arp_hdr->arp_data.arp_tha);
    // add destination ipv4 address
    arp_hdr->arp_data.arp_tip = original_arp_hdr->arp_data.arp_sip;

    packet->port = l2_if->attr.port_id;
    packet->pkt_len = RTE_MAX(packet_length, ETHER_MIN_LEN - ETHER_CRC_LEN);
    packet->data_len = RTE_MAX(packet_length, ETHER_MIN_LEN - ETHER_CRC_LEN);

    packdev_packet_send(packet, l2_if->attr.port_id, 0);
    rte_pktmbuf_free(original_packet);
    RTE_LOG(DEBUG, USER1, "ARP: Sent reply\n");
}

static void packdev_eth_ingress_build(
        struct rte_mbuf *packet,
        struct ether_hdr *eth_hdr,
        packdev_metadata_t *metadata,
        packdev_l2_if_t *l2_if) {
    // Add destination mac
    memcpy(eth_hdr->d_addr.addr_bytes, l2_if->attr.mac_addr, sizeof(l2_if->attr.mac_addr));
    // Add source mac
    memcpy(eth_hdr->s_addr.addr_bytes, metadata->src_mac_addr, sizeof(metadata->src_mac_addr));
    // Add ether type
    eth_hdr->ether_type = rte_cpu_to_be_16(ETHER_TYPE_IPv4);
    // Add vlan header
    if (l2_if->attr.vlan_id != 0) {
        packet->vlan_tci = l2_if->attr.vlan_id;
        rte_vlan_insert(&packet);
        packet->l2_len = OFF_ETH_HDR + OFF_VLAN_HDR;
    } else {
        packet->l2_len = OFF_ETH_HDR;
    }

    // TODO: QUEUEID: fix lcore id to rx/tx queue id
    packdev_packet_send(packet,
            packdev_config_get_veth_port_id(l2_if->attr.port_id), 0);
}

static void packdev_eth_egress_build(
        struct rte_mbuf *packet,
        struct ether_hdr *eth_hdr,
        packdev_metadata_t *metadata,
        packdev_l2_if_t *l2_if) {
    packdev_nbr_t *nbr = packdev_l2_nbr_get(metadata->next_hop_ipv4_addr);
    if (nbr == NULL) {
        // Drop current packet, and send ARP instead
        struct ipv4_hdr *ipv4_hdr = rte_pktmbuf_mtod_offset((packet), struct ipv4_hdr*, OFF_ETH_HDR);
        struct ether_addr empty_mac_addr;
        memset(&empty_mac_addr, 0, sizeof(empty_mac_addr));
        packdev_l2_nbr_add(
                rte_be_to_cpu_32(ipv4_hdr->dst_addr),
                empty_mac_addr.addr_bytes,
                PACKDEV_ORIGIN_FP);
        arp_build_request(packet, l2_if, rte_be_to_cpu_32(ipv4_hdr->src_addr));
    } else if (nbr->state != PACKDEV_ARP_VALID) {
            RTE_LOG(DEBUG, USER1, "ETH: ARP still incomplete, silently drop packet!!!\n");
            rte_pktmbuf_free(packet);
    } else {
        // Add destination mac
        memcpy(eth_hdr->d_addr.addr_bytes, nbr->mac_addr, sizeof(nbr->mac_addr));
        // Add source mac
        memcpy(eth_hdr->s_addr.addr_bytes, l2_if->attr.mac_addr, sizeof(l2_if->attr.mac_addr));
        // Add ether type
        eth_hdr->ether_type = rte_cpu_to_be_16(ETHER_TYPE_IPv4);
        // Add vlan header if required
        if (l2_if->attr.vlan_id != 0) {
            packet->vlan_tci = l2_if->attr.vlan_id;
            rte_vlan_insert(&packet);
            packet->l2_len = OFF_ETH_HDR + OFF_VLAN_HDR;
        } else {
            packet->l2_len = OFF_ETH_HDR;
        }

        // TODO: QUEUEID: fix lcore id to rx/tx queue id
        packdev_packet_send(packet, l2_if->attr.port_id, 0);
    }
}

void packdev_eth_build(struct rte_mbuf *packet) {
    struct ether_hdr *eth_hdr =
        (struct ether_hdr*)rte_pktmbuf_prepend(packet, OFF_ETH_HDR);

    packdev_metadata_t *metadata = PACKDEV_METADATA_PTR(packet);
    packdev_l2_if_t* l2_if = packdev_l2_config_get(metadata->output_l2_if_id);
    if (l2_if != NULL) {
        if (metadata->direction == PACKDEV_INGRESS) {
            packdev_eth_ingress_build(packet, eth_hdr, metadata, l2_if);
        } else {
            packdev_eth_egress_build(packet, eth_hdr, metadata, l2_if);
        }
    } else {
        RTE_LOG(ERR, USER1,
                "ETH: Unable to find L2 interface (id:%u), dropping packet!!!\n",
                metadata->output_l2_if_id);
        rte_pktmbuf_free(packet);
    }
}

static void eth_switch_packet(struct rte_mbuf *packet) {
    packdev_metadata_t *metadata = PACKDEV_METADATA_PTR(packet);
    if (metadata->origin == PACKDEV_ORIGIN_NIC) {
        // TODO: QUEUEID: fix lcore id to rx/tx queue id
        packdev_packet_send(packet, packdev_config_get_veth_port_id(packet->port), 0);
    } else if (metadata->origin == PACKDEV_ORIGIN_VETH) {
        // TODO: QUEUEID: fix lcore id to rx/tx queue id
        packdev_packet_send(packet, packdev_config_get_eth_port_id(packet->port), 0);
    } else {
        RTE_LOG(NOTICE, USER1, "Unknown origin for packet (%u)\n", metadata->origin);
        rte_pktmbuf_free(packet);
    }
}

static void arp_process(
        struct rte_mbuf *packet,
        uint32_t vlan_tag) {
    packdev_metadata_t *metadata = PACKDEV_METADATA_PTR(packet);
    uint32_t eth_port_id = packet->port;
    if (metadata->origin == PACKDEV_ORIGIN_VETH) {
        eth_port_id = packdev_config_get_eth_port_id(packet->port);
    }
    packdev_l2_if_t* l2_if = packdev_l2_config_get_using_vlan_port(vlan_tag, eth_port_id);
    if (l2_if != NULL) {
        struct arp_hdr *arp_hdr = MBUF_ARP_HDR_PTR(packet);
        if (l2_if->attr.vlan_id != 0) {
            arp_hdr = MBUF_ARP_VLAN_HDR_PTR(packet);
        } else {
            arp_hdr = MBUF_ARP_HDR_PTR(packet);
        }

        switch(rte_be_to_cpu_16(arp_hdr->arp_op)) {
        case ARP_OP_REQUEST:
            RTE_LOG(DEBUG, USER1, "ARP: Received request\n");
            if (metadata->origin == PACKDEV_ORIGIN_VETH) {
                struct ether_addr empty_mac_addr;
                memset(&empty_mac_addr, 0, sizeof(empty_mac_addr));
                packdev_l2_nbr_add(
                        rte_be_to_cpu_32(arp_hdr->arp_data.arp_tip),
                        empty_mac_addr.addr_bytes,
                        metadata->origin);
                eth_switch_packet(packet);
            } else if (metadata->origin == PACKDEV_ORIGIN_NIC) {
                // preemptively store NBR
                struct ether_addr empty_mac_addr;
                memset(&empty_mac_addr, 0, sizeof(empty_mac_addr));
                packdev_l2_nbr_add(
                        rte_be_to_cpu_32(arp_hdr->arp_data.arp_sip),
                        empty_mac_addr.addr_bytes,
                        metadata->origin);
                packdev_l2_nbr_set_state(
                        rte_be_to_cpu_32(arp_hdr->arp_data.arp_sip),
                        arp_hdr->arp_data.arp_sha.addr_bytes,
                        PACKDEV_ARP_VALID);
                arp_build_reply(packet, l2_if);
            }
            break;
        case ARP_OP_REPLY:
            RTE_LOG(DEBUG, USER1, "ARP: Received reply\n");
            if (metadata->origin == PACKDEV_ORIGIN_VETH) {
                RTE_LOG(ERR, USER1, "ARP: dropping reply from VETH\n");
                rte_pktmbuf_free(packet);
            } else if (metadata->origin == PACKDEV_ORIGIN_NIC) {
                uint32_t src_ipv4_addr = rte_be_to_cpu_32(arp_hdr->arp_data.arp_sip);
                packdev_nbr_t *nbr = packdev_l2_nbr_get(src_ipv4_addr);
                if (nbr == NULL) {
                    RTE_LOG(ERR, USER1, "ARP: dropping reply from NIC, cannot find NBR entry\n");
                    rte_pktmbuf_free(packet);
                } else {
                    packdev_l2_nbr_set_state(
                            src_ipv4_addr,
                            arp_hdr->arp_data.arp_sha.addr_bytes,
                            PACKDEV_ARP_VALID);
                    if (nbr->origin == PACKDEV_ORIGIN_VETH) {
                        RTE_LOG(DEBUG, USER1, "ARP: switch reply to VETH\n");
                        eth_switch_packet(packet);
                    } else {
                        rte_pktmbuf_free(packet);
                    }
                }
            }
            break;
        default:
            RTE_LOG(ERR, USER1, "ARP: Unknown operation (%u)\n",
                    rte_be_to_cpu_16(arp_hdr->arp_op));
            rte_pktmbuf_free(packet);
            break;
        }
    }
}

static void vlan_process(struct rte_mbuf *packet) {
    struct vlan_hdr *vlan_hdr = MBUF_VLAN_HDR_PTR(packet);
    uint16_t vlan_tag = rte_be_to_cpu_16(vlan_hdr->vlan_tci);
    RTE_LOG(DEBUG, USER1, "VLAN: Received packet with tag: %u\n", vlan_tag);

    packdev_metadata_t *metadata = PACKDEV_METADATA_PTR(packet);
    uint32_t eth_port_id = packet->port;
    if (metadata->origin == PACKDEV_ORIGIN_VETH) {
        eth_port_id = packdev_config_get_eth_port_id(packet->port);
    }
    packdev_l2_if_t* l2_if = packdev_l2_config_get_using_vlan_port(vlan_tag, eth_port_id);
    if (l2_if != NULL) {
        metadata->input_l2_if_id = l2_if->if_id;
        // TODO: output l2_if might change during the course of packet processing
        metadata->output_l2_if_id = l2_if->if_id;

        uint16_t ether_type = rte_be_to_cpu_16(vlan_hdr->eth_proto);
        if (ether_type == ETHER_TYPE_IPv4) {
            if (rte_pktmbuf_adj(packet, OFF_ETH_HDR + OFF_VLAN_HDR) == NULL) {
                RTE_LOG(ERR, USER1,
                        "VLAN: Failed to remove L2 headers, dropping packet!!!\n");
                goto clean_up;
            }

            packdev_ipv4_process(packet);
            return;
        } else if (ether_type == ETHER_TYPE_ARP) {
            arp_process(packet, vlan_tag);
            return;
        } else {
            RTE_LOG(ERR, USER1, "VLAN: Unknown ether type: %u\n", ether_type);
            eth_switch_packet(packet);
            return;
        }

    } else {
        RTE_LOG(ERR, USER1, "VLAN: Unconfigured VLAN tag/port, dropping packet\n");
        goto clean_up;
    }

clean_up:
    rte_pktmbuf_free(packet);
}

static void ipv4_process(struct rte_mbuf *packet) {
    uint32_t vlan_tag = 0;
    packdev_metadata_t *metadata = PACKDEV_METADATA_PTR(packet);
    uint32_t eth_port_id = packet->port;
    if (metadata->origin == PACKDEV_ORIGIN_VETH) {
        eth_port_id = packdev_config_get_eth_port_id(packet->port);
    }
    packdev_l2_if_t* l2_if = packdev_l2_config_get_using_vlan_port(vlan_tag, eth_port_id);
    if (l2_if != NULL) {
        metadata->input_l2_if_id = l2_if->if_id;
        // TODO: output l2_if might change during the course of packet processing
        metadata->output_l2_if_id = l2_if->if_id;

        if (rte_pktmbuf_adj(packet, OFF_ETH_HDR) == NULL) {
            RTE_LOG(ERR, USER1,
                    "ETH: Failed to remove ethernet header, dropping packet!!!\n");
            goto clean_up;
        }

        /* Frees the mbuf */
        packdev_ipv4_process(packet);
        return;
    } else {
        RTE_LOG(ERR, USER1, "ETH: Unconfigured VLAN tag/port, dropping packet\n");
        goto clean_up;
    }

clean_up:
    rte_pktmbuf_free(packet);
}

void packdev_eth_process(struct rte_mbuf *packet) {
    struct ether_hdr *eth_hdr = MBUF_ETH_HDR_PTR(packet);
    uint16_t ether_type = rte_be_to_cpu_16(eth_hdr->ether_type);
    packdev_eth_print_addr(eth_hdr->s_addr);
    packdev_eth_print_addr(eth_hdr->d_addr);

    packdev_metadata_t *metadata = PACKDEV_METADATA_PTR(packet);
    memcpy(metadata->src_mac_addr, eth_hdr->s_addr.addr_bytes, sizeof(eth_hdr->s_addr.addr_bytes));
    switch (ether_type) {
    case ETHER_TYPE_ARP:
        arp_process(packet, 0);
        break;
    case ETHER_TYPE_VLAN:
        vlan_process(packet);
        break;
    case ETHER_TYPE_IPv4:
        ipv4_process(packet);
        break;
    default:
        RTE_LOG(INFO, USER1, "Unknown ether type: %u\n", ether_type);
        RTE_LOG(INFO, USER1, "Do not know how to handle ether type: %u\n", ether_type);
        eth_switch_packet(packet);
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

