
/* Fast Path packet processing prototype

   see also: ip_fastpath.h

   sven.s.stenstrom@ericsson.com

 */

#include <stdint.h>
#include <unistd.h>

#include <rte_mbuf.h>
#include <rte_ether.h>

struct ether_hdr* packdev_eth_get_hdr(struct rte_mbuf *mbuf) {
    return rte_pktmbuf_mtod(mbuf, struct ether_hdr *);
}

uint16_t packdev_eth_get_type(struct rte_mbuf *mbuf) {
    struct ether_hdr *eth_hdr = packdev_eth_get_hdr(mbuf);
    return (uint16_t)rte_bswap16(eth_hdr->ether_type);
}

void packdev_eth_print_addr(struct ether_addr addr) {
    RTE_LOG(DEBUG, USER1,
            "MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
            " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
            addr.addr_bytes[0], addr.addr_bytes[1],
            addr.addr_bytes[2], addr.addr_bytes[3],
            addr.addr_bytes[4], addr.addr_bytes[5]);
}
