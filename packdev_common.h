#ifndef PACKDEV_COMMON_H_
#define PACKDEV_COMMON_H_

#include <rte_eal.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ip.h>


enum {
    DEFAULT_PKT_BURST       = 32,

    /* Following comment copied from rte_mempool.h
       If cache_size is non-zero, the rte_mempool library will try to limit
       the accesses to the common lockless pool, by maintaining a per-lcore
       object cache. This argument must be lower or equal to
       CONFIG_RTE_MEMPOOL_CACHE_MAX_SIZE and n / 1.5.
       It is advised to choose cache_size to have "n modulo cache_size == 0":
       if this is not the case, some elements will always stay in the pool
       and will never be used. The access to the per-lcore table is
       of course faster than the multi-producer/consumer pool.
       The cache can be disabled if the cache_size argument is set to 0;
       it can be useful to avoid losing objects in cache. */
    DEFAULT_RX_DESC          = (DEFAULT_PKT_BURST * 4),
    MAX_RX_MBUFS_PER_PORT    = (DEFAULT_RX_DESC * 4),
    MBUF_RX_CACHE_SIZE       = (MAX_RX_MBUFS_PER_PORT / 8),

    DEFAULT_TX_DESC          = (DEFAULT_PKT_BURST * 32),
    MAX_TX_MBUFS             = (DEFAULT_TX_DESC * 4),
    MBUF_TX_CACHE_SIZE       = (MAX_TX_MBUFS / 8),

    NUM_RX_QUEUES_PER_PORT   = 1,    /**< Number of rx cores per port. */
    NUM_TX_QUEUES_PER_PORT   = 1,    /**< Number of tx cores per port. */

    MAX_NUM_OF_PORTS         = 4,
    MAX_NUM_QUEUES_PER_PORT  = 4,

    MAX_ACL_CATEGORIES       = 1,
    MAX_ACL_RULES            = 128,

    MAX_REASSEMBLY_FLOWS     = 1024,
    MAX_REASSEMBLY_FRAGMENTS = 4,
    REASSEMBLY_TIMER_MS      = 100,

    MAX_NUM_OF_SAS           = 128,

    MAX_ENCR_KEY_LENGTH      = 128,
    MAX_AUTH_KEY_LENGTH      = 128,

    MAX_NUM_CRYPTO_MBUFS     = 1024,
    CRYPTO_CACHE_SIZE        = 128,
    MAX_NUM_CRYPTO_SESSIONS  = 1024,
    CRYPTO_MESSAGE_LENGTH    = 1024,
    MAX_IV_LENGTH            = 16,
};

/* RFC4303 */
struct esp_hdr {
    uint32_t spi;
    uint32_t seq;
    /* Payload */
    /* Padding */
    /* Pad Length */
    /* Next Header */
    /* Integrity Check Value - ICV */
};

#define OFF_ETH_HDR    (sizeof(struct ether_hdr))
#define OFF_IPV4_HDR   (sizeof(struct ipv4_hdr))
#define OFF_ESP_HDR   (sizeof(struct esp_hdr))
#define MBUF_IP_HDR_OFFSET(m)   \
    rte_pktmbuf_mtod_offset((m), uint8_t *, OFF_ETH_HDR)
#define MBUF_IPV4_UDP_HDR_OFFSET(m)   \
    rte_pktmbuf_mtod_offset((m), uint8_t *, OFF_ETH_HDR + OFF_IPV4_HDR)
#define MBUF_IPV4_ESP_HDR_OFFSET(m)   \
    rte_pktmbuf_mtod_offset((m), uint8_t *, OFF_ETH_HDR + OFF_IPV4_HDR)

#define MBUF_INNER_IP_HDR_OFFSET(m)   \
    rte_pktmbuf_mtod_offset((m), uint8_t *, 0)
#define MBUF_INNER_IPV4_UDP_HDR_OFFSET(m)   \
    rte_pktmbuf_mtod_offset((m), uint8_t *, OFF_IPV4_HDR)


#define MBUF_IPV4_ESP_DATA_OFFSET(m, len)   \
    rte_pktmbuf_mtod_offset((m), uint8_t *, OFF_ETH_HDR + OFF_IPV4_HDR + OFF_ESP_HDR + len)
#define MBUF_IPV4_ESP_DATA_PHY_OFFSET(m, len)   \
    rte_pktmbuf_mtophys_offset((m), OFF_ETH_HDR + OFF_IPV4_HDR + OFF_ESP_HDR + len)

#define MBUF_IPV4_ESP_IV_OFFSET(m) MBUF_IPV4_ESP_DATA_OFFSET(m, 0)
#define MBUF_IPV4_ESP_IV_PHY_OFFSET(m) MBUF_IPV4_ESP_DATA_PHY_OFFSET(m, 0)

#define MBUF_IPV4_ESP_DIGEST_OFFSET(m, digest_len)   \
    rte_pktmbuf_mtod_offset((m), uint8_t *, rte_pktmbuf_pkt_len(m) - digest_len)
#define MBUF_IPV4_ESP_DIGEST_PHY_OFFSET(m, digest_len)   \
    rte_pktmbuf_mtophys_offset((m), rte_pktmbuf_pkt_len(m) - digest_len)

#define SYM_IV_OFFSET  (sizeof(struct rte_crypto_op) + \
        sizeof(struct rte_crypto_sym_op))

#endif // PACKDEV_COMMON_H_
