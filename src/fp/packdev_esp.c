
/* Fast Path packet processing prototype

   see also: ip_fastpath.h

   sven.s.stenstrom@ericsson.com

 */

#include <sys/types.h>
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>

#include <rte_eal.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_acl.h>
#include <rte_common.h>
#include <rte_log.h>
#include <rte_hexdump.h>

#include "sys/packdev_common.h"
#include "sys/packdev_packet.h"
#include "sys/packdev_port.h"

#include "cp/packdev_ipv4_flow.h"
#include "cp/packdev_sa_config.h"
#include "cp/packdev_spd_config.h"

#include "fp/packdev_ipv4.h"
#include "fp/packdev_esp.h"

static void esp_inbound_pre_process(struct rte_mbuf *packet);
static void esp_inbound_post_process(struct rte_mbuf *packet, packdev_sa_t *sa);
static void esp_outbound_pre_process(struct rte_mbuf *packet);
static void esp_outbound_post_process(struct rte_mbuf *packet, packdev_sa_t *sa);

static packdev_sa_t* spi_lookup(
        uint32_t spi,
        uint32_t local_addr,
        uint32_t remote_addr) {
    struct sa_attr_t attr = {
        .spi = spi,
        .local_addr = local_addr,
        .remote_addr = remote_addr,
    };
    uint32_t sa_id = 0;
    uint32_t key = rte_jhash(&attr, sizeof(attr), SA_TABLE_IV);
    RTE_LOG(DEBUG, USER1, "SA: Received packet with key = 0x%08x\n", key);

    int lookup_result = rte_hash_lookup_data(
            packdev_sa_config_get_table(),
            &key,
            (void**)(&sa_id));
    if (lookup_result >= 0) {
        return packdev_sa_config_get(sa_id);
    }

    switch(lookup_result) {
    case -ENOENT:
        RTE_LOG(DEBUG, USER1, "SA: Key not found\n");
        break;
    case -EINVAL:
        RTE_LOG(DEBUG, USER1, "SA: Invalid hash parameter\n");
        break;
    default:
        RTE_LOG(DEBUG, USER1, "SA: Unexpected error on lookup (%d)\n", lookup_result);
        break;
    };

    return NULL;
}

static packdev_policy_t* spd_lookup(struct rte_mbuf *packet) {
    packdev_metadata_t *metadata = PACKDEV_METADATA_PTR(packet);
    uint32_t policy_id = packdev_ipv4_flow_classify(PACKDEV_FLOW_TYPE_SPD, packet);
    packdev_policy_t *policy = packdev_spd_config_get(policy_id);
    if (policy == NULL) {
        RTE_LOG(ERR, USER1, "ESP: Cannot find policy in SPD\n");
        goto not_found;
    }

    packdev_spd_result_t spd_result = policy->action;
    switch(spd_result) {
    case PACKDEV_SPD_PROTECT:
        RTE_LOG(DEBUG, USER1, "ESP: SPD result protect, continue processing!\n");
        break;
    case PACKDEV_SPD_DISCARD:
        RTE_LOG(NOTICE, USER1, "ESP: SPD result discard, dropping packet!!!\n");
        goto not_found;
    case PACKDEV_SPD_BYPASS:
    default:
        RTE_LOG(NOTICE, USER1, "ESP: SPD result unknown (%u), dropping packet!!!\n",
                spd_result);
        goto not_found;
    }

    metadata->inner_packet = true;
    return policy;

not_found:
    metadata->inner_packet = false;
    return NULL;
}

static bool esp_enqueue_crypto_operation(
        struct rte_mbuf *packet,
        packdev_sa_t *sa) {
    packdev_crypto_dev_t *crypto_dev = sa->crypto_dev;
    uint16_t num_crypto_ops = 1;
    struct rte_crypto_op *crypto_op = rte_crypto_op_alloc(
            crypto_dev->operation_pool,
            RTE_CRYPTO_OP_TYPE_SYMMETRIC);
    crypto_op->type = RTE_CRYPTO_OP_TYPE_SYMMETRIC;
    crypto_op->status = RTE_CRYPTO_OP_STATUS_NOT_PROCESSED;
    rte_crypto_op_attach_sym_session(crypto_op, sa->session);

    uint16_t protected_data_length =
        rte_pktmbuf_pkt_len(packet) -
        sizeof(struct ipv4_hdr) -
        sizeof(struct esp_hdr) -
        sa->iv_length -
        sa->digest_length;

    uint16_t authenticated_data_length =
        rte_pktmbuf_pkt_len(packet) -
        sizeof(struct ipv4_hdr) -
        sa->digest_length;

    uint32_t inner_hdr_offset =
        sizeof(struct ipv4_hdr) +
        sizeof(struct esp_hdr) +
        sa->iv_length;
    crypto_op->sym->cipher.data.length = protected_data_length;
    crypto_op->sym->cipher.data.offset = inner_hdr_offset;

    uint8_t *packet_iv = (uint8_t*)MBUF_IPV4_ESP_IV_OFFSET(packet);
    uint8_t *crypto_iv = rte_crypto_op_ctod_offset(
            crypto_op,
            uint8_t*,
            SYM_IV_OFFSET);
    rte_memcpy(crypto_iv, packet_iv, sa->iv_length);

    crypto_op->sym->auth.data.length = authenticated_data_length;
    crypto_op->sym->auth.data.offset = sizeof(struct ipv4_hdr);

    crypto_op->sym->auth.digest.data = MBUF_IPV4_ESP_DIGEST_OFFSET(packet, sa->digest_length);
    crypto_op->sym->auth.digest.phys_addr = MBUF_IPV4_ESP_DIGEST_PHY_OFFSET(packet, sa->digest_length);

#if 0
    rte_pktmbuf_dump(stdout, packet, packet->data_len);

    rte_hexdump(stdout, "Cipher data:",
            rte_pktmbuf_mtod_offset(
                packet,
                uint8_t*,
                crypto_op->sym->cipher.data.offset),
            crypto_op->sym->cipher.data.length);

    rte_hexdump(stdout, "Cipher IV(packet):",
            packet_iv,
            sa->iv_length);

    rte_hexdump(stdout, "Cipher IV(crypto op):",
            crypto_iv,
            sa->iv_length);

    rte_hexdump(stdout, "Auth data:",
            rte_pktmbuf_mtod_offset(
                packet,
                uint8_t*,
                crypto_op->sym->auth.data.offset),
            crypto_op->sym->auth.data.length);

    rte_hexdump(stdout, "Auth digest:",
            crypto_op->sym->auth.digest.data,
            sa->digest_length);
#endif

    crypto_op->sym->m_src = packet;
    crypto_op->sym->m_dst = NULL;

    uint16_t enq_result = rte_cryptodev_enqueue_burst(
            crypto_dev->id,
            crypto_dev->qp_id,
            &crypto_op,
            num_crypto_ops);
    if (enq_result < num_crypto_ops) {
        RTE_LOG(ERR, USER1, "ESP: cryptodev enqueue failed(%u)!!!\n",
                crypto_op->status);
        rte_crypto_op_free(crypto_op);
        return false;
    }

    return true;
}

static void esp_inbound_pre_process(struct rte_mbuf *packet) {
    struct ipv4_hdr *ipv4_hdr = MBUF_IPV4_HDR_PTR(packet);
    struct esp_hdr *esp_hdr = MBUF_IPV4_ESP_HDR_PTR(packet);
    uint32_t spi = rte_be_to_cpu_32(esp_hdr->spi);
    RTE_LOG(DEBUG, USER1, "ESP: Received SPI: (0x%08x)\n", rte_be_to_cpu_32(esp_hdr->spi));
    RTE_LOG(DEBUG, USER1, "ESP: Received SEQ no: (%u)\n", rte_be_to_cpu_32(esp_hdr->seq));
#if 0
    RTE_LOG(DEBUG, USER1, "ESP: Received local_addr: (0x%08x)\n", rte_be_to_cpu_32(ipv4_hdr->dst_addr));
    RTE_LOG(DEBUG, USER1, "ESP: Received remote_addr: (0x%08x)\n", rte_be_to_cpu_32(ipv4_hdr->src_addr));
#endif

    packdev_sa_t *sa = spi_lookup(
            spi,
            rte_be_to_cpu_32(ipv4_hdr->dst_addr),
            rte_be_to_cpu_32(ipv4_hdr->src_addr));
    if (sa == NULL) {
        RTE_LOG(ERR, USER1, "ESP: SA with SPI (%u) not found\n", spi);
        goto clean_up;
    }

    RTE_LOG(DEBUG, USER1, "ESP: Found SA (index:%u) for SPI: (%u)\n", sa->sa_id, spi);

    // TODO 2018-01-02: Perform sequence number check

    if (esp_enqueue_crypto_operation(packet, sa)) {
        esp_inbound_post_process(packet, sa);
        return;
    }

clean_up:
    if (packet) {
        rte_pktmbuf_free(packet);
    }
}

static void esp_inbound_post_process(
        struct rte_mbuf *packet,
        packdev_sa_t *sa) {
    packdev_crypto_dev_t *crypto_dev = sa->crypto_dev;
    uint32_t inner_hdr_offset =
        sizeof(struct ipv4_hdr) +
        sizeof(struct esp_hdr) +
        sa->iv_length;

    struct rte_crypto_op *crypto_op = NULL;
    uint16_t num_crypto_ops = 1;
    uint16_t count = 1;
    uint16_t dequeue_result = 0;
    while (dequeue_result != num_crypto_ops) {
        RTE_LOG(DEBUG, USER1, "ESP: cryptodev dequeue try#%u\n", count++);
        dequeue_result = rte_cryptodev_dequeue_burst(
            crypto_dev->id,
            crypto_dev->qp_id,
            &crypto_op,
            num_crypto_ops);
    }

    if (crypto_op->status != RTE_CRYPTO_OP_STATUS_SUCCESS) {
        RTE_LOG(ERR, USER1, "ESP: cryptodev dequeue failed (status:%u)!!!\n",
                crypto_op->status);
        goto clean_up;
    }

    packet = crypto_op->sym->m_src;
    if (packet == NULL) {
        goto clean_up;
    }

    rte_crypto_op_free(crypto_op);
    crypto_op = NULL;


    // Remove all padding bytes if necessary
    uint8_t *next_hdr = rte_pktmbuf_mtod_offset(packet, uint8_t*,
            rte_pktmbuf_pkt_len(packet) - sa->digest_length - 1);
    uint8_t *pad_length_ptr = next_hdr - 1;
    uint8_t *padding_ptr = pad_length_ptr - (*pad_length_ptr);
    for (uint8_t i = 0; i < *pad_length_ptr; i++) {
        if (padding_ptr[i] != i + 1) {
            RTE_LOG(ERR, USER1, "ESP: Invalid padding\n");
            goto clean_up;
        }
    }

    if (rte_pktmbuf_adj(packet, inner_hdr_offset) == NULL) {
        RTE_LOG(ERR, USER1, "ESP: Failed to remove outer headers, dropping packet!!!\n");
        goto clean_up;
    }

    if (rte_pktmbuf_trim(packet, *pad_length_ptr + 2) ||
            rte_pktmbuf_trim(packet, sa->digest_length)) {
        RTE_LOG(ERR, USER1, "ESP: Failed to remove digest and padding, dropping packet!!!\n");
        goto clean_up;
    }

    packdev_policy_t *policy = spd_lookup(packet);
    if (policy) {
        if (policy->sa_id != sa->sa_id) {
            RTE_LOG(ERR, USER1, "ESP: Packet received on invalid SA, dropping packet!!!\n");
            goto clean_up;
        }

        packdev_ipv4_process(packet);

        packdev_metadata_t *metadata = PACKDEV_METADATA_PTR(packet);
        metadata->consumed = true;
        return;
    }

clean_up:
    if (packet) {
        rte_pktmbuf_free(packet);
    }

    if (crypto_op) {
        rte_crypto_op_free(crypto_op);
    }
}

static void esp_outbound_pre_process(struct rte_mbuf *packet) {
    packdev_policy_t *policy = spd_lookup(packet);
    if (policy == NULL) {
        RTE_LOG(ERR, USER1, "ESP: No matching outbound policy in SPD\n");
        return;
    }

    uint32_t sa_id = policy->sa_id;
    packdev_sa_t *sa = packdev_sa_config_get(sa_id);
    if (sa == NULL) {
        RTE_LOG(ERR, USER1, "ESP: SA with id(%u) not found\n", sa_id);
        goto clean_up;
    } else {
        RTE_LOG(DEBUG, USER1, "ESP: Encrypt using SA with id(%u)\n", sa_id);
    }

    /* Padded payload length */
    uint32_t esp_trailer_length = 2; /* pad length (1 byte) + next header (1 byte) */
    uint32_t esp_payload_length = RTE_ALIGN_CEIL(
            rte_pktmbuf_pkt_len(packet) + esp_trailer_length,
            sa->block_size);
    uint32_t pad_length = esp_payload_length - rte_pktmbuf_pkt_len(packet) - esp_trailer_length;

    /* Add ESP header */
    struct esp_hdr *esp_hdr =
        (struct esp_hdr*)rte_pktmbuf_prepend(packet, OFF_ESP_HDR + sa->iv_length);
    if (esp_hdr == NULL) {
        RTE_LOG(ERR, USER1, "ESP: Could not prepend ESP header\n");
        goto clean_up;
    }
    esp_hdr->spi = rte_cpu_to_be_32(sa->attr.spi);
    esp_hdr->seq = rte_cpu_to_be_32(++sa->sequence_num);

    /* Add padding if necessary */
    uint8_t *padding = (uint8_t*)rte_pktmbuf_append(packet, pad_length + esp_trailer_length + sa->digest_length);
    if (padding) {
        /* Fill padding using default sequential scheme */
        for (uint32_t i = 0; i < pad_length; i++) {
            padding[i] = i + 1;
        }
        /* padding length */
        padding[pad_length] = pad_length;
        /* next header: hard coded to IPv4 */
        padding[pad_length + 1] = IPPROTO_IPIP;
    } else {
        RTE_LOG(ERR, USER1, "ESP: SA(%u): could not append padding bytes(%u)\n", sa_id, pad_length);
        goto clean_up;
    }
    /* Add outer IPv4 header */
    struct ipv4_hdr *outer_ipv4_hdr =
        (struct ipv4_hdr*)rte_pktmbuf_prepend(packet, OFF_IPV4_HDR);
    if (outer_ipv4_hdr == NULL) {
        RTE_LOG(ERR, USER1, "ESP: Could not prepend outer IPv4 header\n");
        goto clean_up;
    }
    outer_ipv4_hdr->version_ihl = 0x45;
    outer_ipv4_hdr->type_of_service = 0;
    outer_ipv4_hdr->total_length = rte_cpu_to_be_16(rte_pktmbuf_pkt_len(packet));
    outer_ipv4_hdr->packet_id = 0;
    outer_ipv4_hdr->fragment_offset = 0;
    outer_ipv4_hdr->fragment_offset &= ~rte_cpu_to_be_16(IPV4_HDR_DF_FLAG);
    outer_ipv4_hdr->time_to_live = DEF_IPV4_TTL;
    outer_ipv4_hdr->next_proto_id = IPPROTO_ESP;
    outer_ipv4_hdr->hdr_checksum = 0;
    outer_ipv4_hdr->src_addr = rte_cpu_to_be_32(sa->attr.local_addr);
    outer_ipv4_hdr->dst_addr = rte_cpu_to_be_32(sa->attr.remote_addr);

    if (esp_enqueue_crypto_operation(packet, sa)) {
        esp_outbound_post_process(packet, sa);
        return;
    }

clean_up:
    if (packet) {
        rte_pktmbuf_free(packet);
    }
}

static void esp_outbound_post_process(
        struct rte_mbuf *packet,
        packdev_sa_t *sa) {
    packdev_crypto_dev_t *crypto_dev = sa->crypto_dev;

    struct rte_crypto_op *crypto_op = NULL;
    uint16_t num_crypto_ops = 1;
    uint16_t count = 1;
    uint16_t dequeue_result = 0;
    while (dequeue_result != num_crypto_ops) {
        RTE_LOG(DEBUG, USER1, "ESP: cryptodev dequeue try#%u\n", count++);
        dequeue_result = rte_cryptodev_dequeue_burst(
            crypto_dev->id,
            crypto_dev->qp_id,
            &crypto_op,
            num_crypto_ops);
    }

    if (crypto_op->status != RTE_CRYPTO_OP_STATUS_SUCCESS) {
        RTE_LOG(ERR, USER1, "ESP: crypto operation failed (status:%u)!!!\n",
                crypto_op->status);
        goto clean_up;
    }

    packet = crypto_op->sym->m_src;
    if (packet == NULL) {
        goto clean_up;
    }

    rte_crypto_op_free(crypto_op);
    crypto_op = NULL;

    packdev_ipv4_process(packet);

    packdev_metadata_t *metadata = PACKDEV_METADATA_PTR(packet);
    metadata->consumed = true;
    return;

clean_up:
    if (packet) {
        rte_pktmbuf_free(packet);
    }

    if (crypto_op) {
        rte_crypto_op_free(crypto_op);
    }
}

void packdev_esp_build(struct rte_mbuf *packet) {
    esp_outbound_pre_process(packet);
}

void packdev_esp_process(struct rte_mbuf *packet) {
    esp_inbound_pre_process(packet);
}
