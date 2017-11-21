#ifndef PACKDEV_ETH_H_
#define PACKDEV_ETH_H_

#include <rte_ether.h>

struct ether_hdr* packdev_eth_get_hdr(struct rte_mbuf *mbuf);

uint16_t packdev_eth_get_type(struct rte_mbuf *mbuf);

void packdev_eth_print_addr(struct ether_addr addr);

#endif /* PACKDEV_ETH_H_ */

