#ifndef PACKDEV_COMMON_H_
#define PACKDEV_COMMON_H_

#include <rte_eal.h>
#include <rte_mbuf.h>
#include <rte_arp.h>
#include <rte_ether.h>
#include <rte_ip.h>


enum {
    DEFAULT_MBUF_PRIV_SIZE  = 32,
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

    MAX_NUM_L2_IFS           = MAX_NUM_OF_PORTS,
    MAX_NUM_NBRS             = 256,
    MAX_NUM_VLAN_PER_PORT    = 4,
    MAX_NUM_L3_IFS           = MAX_NUM_OF_PORTS * MAX_NUM_VLAN_PER_PORT,
    MAX_NUM_ROUTES           = 256,
    MAX_NUM_NEXT_HOPS        = 256,

    MAX_ACL_CATEGORIES       = 1,
    MAX_NUM_ACLS             = 128,
    MAX_NUM_POLICIES         = 128,
    MAX_NUM_SESSIONS         = 128,

    DEF_IPV4_TTL             = 64,
    MAX_NUM_FRAGMENTS        = 4,
    MAX_REASSEMBLY_FLOWS     = 8192,
    MAX_REASSEMBLY_FRAGMENTS = 4,
    REASSEMBLY_TIMER_MS      = 2000,

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

typedef enum {
    PACKDEV_ORIGIN_NIC,
    PACKDEV_ORIGIN_VETH,
    PACKDEV_ORIGIN_FP,
    PACKDEV_ORIGIN_MAX
} packdev_packet_origin_t;

typedef enum {
    PACKDEV_INGRESS,
    PACKDEV_EGRESS,
    PACKDEV_DIR_MAX
} packdev_packet_direction_t;

typedef struct {
    uint16_t origin;
    uint16_t inner_packet;
    uint16_t direction;
    uint16_t consumed;
    uint8_t src_mac_addr[8];
    uint8_t input_l2_if_id;
    uint8_t input_l3_if_id;
    uint8_t output_l2_if_id;
    uint8_t output_l3_if_id;
    uint32_t next_hop_ipv4_addr;
} packdev_metadata_t;

#define PACKDEV_METADATA_PTR(packet) \
    ((packdev_metadata_t*) ((uintptr_t) packet + sizeof(struct rte_mbuf)))

#define PACKDEV_METADATA_COPY(dst_packet, src_packet) \
    memcpy( \
            PACKDEV_METADATA_PTR(dst_packet), \
            PACKDEV_METADATA_PTR(src_packet), \
            sizeof(packdev_metadata_t));

#define OFF_ETH_HDR    (sizeof(struct ether_hdr))
#define OFF_VLAN_HDR   (sizeof(struct vlan_hdr))
#define OFF_ARP_HDR    (sizeof(struct arp_hdr))
#define OFF_IPV4_HDR   (sizeof(struct ipv4_hdr))
#define OFF_ESP_HDR   (sizeof(struct esp_hdr))
#define MBUF_ETH_HDR_PTR(m) \
    rte_pktmbuf_mtod((m), struct ether_hdr*)
#define MBUF_ARP_HDR_PTR(m) \
    rte_pktmbuf_mtod_offset((m), struct arp_hdr*, OFF_ETH_HDR)
#define MBUF_ARP_VLAN_HDR_PTR(m) \
    rte_pktmbuf_mtod_offset((m), struct arp_hdr*, OFF_ETH_HDR + OFF_VLAN_HDR)
#define MBUF_VLAN_HDR_PTR(m) \
    rte_pktmbuf_mtod_offset((m), struct vlan_hdr*, OFF_ETH_HDR)
#define MBUF_IPV4_HDR_PTR(m) \
    rte_pktmbuf_mtod((m), struct ipv4_hdr*)
#define MBUF_IPV4_ICMP_HDR_PTR(m) \
    rte_pktmbuf_mtod_offset((m), struct udp_hdr*, OFF_IPV4_HDR)
#define MBUF_IPV4_UDP_HDR_PTR(m) \
    rte_pktmbuf_mtod_offset((m), struct udp_hdr*, OFF_IPV4_HDR)
#define MBUF_IPV4_TCP_HDR_PTR(m) \
    rte_pktmbuf_mtod_offset((m), struct udp_hdr*, OFF_IPV4_HDR)
#define MBUF_IPV4_ESP_HDR_PTR(m) \
    rte_pktmbuf_mtod_offset((m), struct esp_hdr*, OFF_IPV4_HDR)

#define MBUF_IPV4_ESP_DATA_OFFSET(m, len)   \
    rte_pktmbuf_mtod_offset((m), uint8_t *, OFF_IPV4_HDR + OFF_ESP_HDR + len)
#define MBUF_IPV4_ESP_DATA_PHY_OFFSET(m, len)   \
    rte_pktmbuf_mtophys_offset((m), OFF_IPV4_HDR + OFF_ESP_HDR + len)

#define MBUF_IPV4_ESP_IV_OFFSET(m) MBUF_IPV4_ESP_DATA_OFFSET(m, 0)
#define MBUF_IPV4_ESP_IV_PHY_OFFSET(m) MBUF_IPV4_ESP_DATA_PHY_OFFSET(m, 0)

#define MBUF_IPV4_ESP_DIGEST_OFFSET(m, digest_len)   \
    rte_pktmbuf_mtod_offset((m), uint8_t *, rte_pktmbuf_pkt_len(m) - digest_len)
#define MBUF_IPV4_ESP_DIGEST_PHY_OFFSET(m, digest_len)   \
    rte_pktmbuf_mtophys_offset((m), rte_pktmbuf_pkt_len(m) - digest_len)

#define SYM_IV_OFFSET  (sizeof(struct rte_crypto_op) + \
        sizeof(struct rte_crypto_sym_op))

#endif // PACKDEV_COMMON_H_
