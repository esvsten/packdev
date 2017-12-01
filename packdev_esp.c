
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

#include "packdev_common.h"
#include "packdev_crypto.h"
#include "packdev_ipv4.h"
#include "packdev_packet.h"
#include "packdev_acl_config.h"
#include "packdev_sa_config.h"
#include "packdev_spd_config.h"

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

static void esp_downlink_process(
        struct rte_mbuf *packet,
        packdev_sa_t *sa) {
    packdev_crypto_dev_t *crypto_dev = packdev_crypto_get_device();
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

    uint16_t enq_result = rte_cryptodev_enqueue_burst(
            crypto_dev->id,
            crypto_dev->qp_id,
            &crypto_op,
            num_crypto_ops);
    if (enq_result < num_crypto_ops) {
        RTE_LOG(ERR, USER1, "ESP: cryptodev enqueue failed!!!\n");
        goto clean_up;
    }

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

    packet = crypto_op->sym->m_src;
    if (packet == NULL) {
        goto clean_up;
    }

    if (crypto_op->status != RTE_CRYPTO_OP_STATUS_SUCCESS) {
        RTE_LOG(ERR, USER1, "ESP: crypto operation failed (status:%u)!!!\n",
                crypto_op->status);
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

    packdev_metadata_t *metadata = PACKDEV_METADATA_PTR(packet);
    metadata->inner_packet = true;
    packdev_ipv4_process(packet);
    return;

clean_up:
    if (packet) {
        rte_pktmbuf_free(packet);
    }

    if (crypto_op) {
        rte_crypto_op_free(crypto_op);
    }
}

void packdev_esp_process(struct rte_mbuf *packet) {
    struct ipv4_hdr *ipv4_hdr = MBUF_IPV4_HDR_PTR(packet);
    struct esp_hdr *esp_hdr = MBUF_IPV4_ESP_HDR_PTR(packet);
    uint32_t spi = rte_bswap32(esp_hdr->spi);
    RTE_LOG(DEBUG, USER1, "ESP: Received SPI: (0x%08x)\n", rte_bswap32(esp_hdr->spi));
    RTE_LOG(DEBUG, USER1, "ESP: Received SEQ no: (%u)\n", rte_bswap32(esp_hdr->seq));
#if 0
    RTE_LOG(DEBUG, USER1, "ESP: Received local_addr: (0x%08x)\n", rte_bswap32(ipv4_hdr->dst_addr));
    RTE_LOG(DEBUG, USER1, "ESP: Received remote_addr: (0x%08x)\n", rte_bswap32(ipv4_hdr->src_addr));
#endif

    packdev_sa_t *sa = spi_lookup(
            spi,
            rte_bswap32(ipv4_hdr->dst_addr),
            rte_bswap32(ipv4_hdr->src_addr));
    if (sa != NULL) {
        RTE_LOG(DEBUG, USER1, "ESP: Found SA (index:%u) for SPI: (%u)\n",
                sa->sa_id, spi);
        esp_downlink_process(packet, sa);
    }
}
